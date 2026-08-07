using System.Data.Common;
using Dapper;
using Npgsql;

namespace Dependably.Infrastructure;

/// <summary>
/// Retrofits the canonical-timestamp CHECK (<see cref="TemporalCheckPredicate.ForPostgres"/>) onto
/// an EXISTING Postgres database, so an upgraded instance ends up with the same constraint a fresh
/// install gets from its <c>CREATE TABLE</c> block. Postgres only: SQLite has no
/// <c>ALTER TABLE … ADD CONSTRAINT</c>, and a fresh SQLite install already carries the CHECK from
/// <c>Schema.sql</c>.
///
/// <para><b>The column set is derived, never listed.</b> <see cref="SchemaSqlParser"/> parses the
/// same embedded <c>Schema.pg.sql</c> text <c>ApplySchemaAsync</c> just executed, and every column
/// whose declaration contains the exact <see cref="TemporalCheckPredicate.ForPostgres"/> literal is
/// retrofitted. A hand-copied list of 132 pairs would be a second source of truth that drifts the
/// first time a column is added to one and not the other — and drifts silently, because a missing
/// entry produces no error, just a column nobody ever constrains. Deriving from the schema text
/// also rules out the tempting alternative of scanning <c>information_schema.columns</c> for
/// temporally-named TEXT columns: that would sweep in <c>_applied_migrations.applied_at</c>, which
/// is a real <c>*_at</c> TEXT column but is created by <c>EnsureMigrationsTableAsync</c> rather than
/// by <c>Schema.pg.sql</c>, carries no CHECK on a fresh install, and so must not acquire one here.</para>
///
/// <para><b>Runs on every boot, not once through the <c>_applied_migrations</c> ledger.</b>
/// Idempotency comes from the per-column <c>pg_constraint</c> lookup, which costs one catalogue
/// probe per column on a database that is already fully constrained. A ledger entry would record
/// "the retrofit ran" against the column set that existed on the day it ran, and every temporal
/// column added by a later release would then be constrained on fresh installs and never on
/// upgraded ones — a gap that widens with each release and that nothing reports. Deriving the set
/// from the schema on every boot means a column added to a future <c>CREATE TABLE</c> block is
/// picked up the first time a binary carrying it boots, with no new migration code.</para>
///
/// <para><b>Add is <c>NOT VALID</c>; validation is best-effort and per column.</b>
/// <c>ADD CONSTRAINT … NOT VALID</c> takes a brief <c>ACCESS EXCLUSIVE</c> lock and skips the table
/// scan, but still enforces the predicate on every subsequent INSERT/UPDATE — so new writes are
/// constrained the moment the boot completes, whatever the state of the existing rows. The
/// follow-up <c>VALIDATE CONSTRAINT</c> is what scans and marks the constraint proven; it runs
/// under <c>SHARE UPDATE EXCLUSIVE</c>, so serving replicas keep reading and writing throughout.
/// Its failure mode is the interesting one: a legacy row this release's self-healing sweep does not
/// reach (<see cref="SchemaInitializer.TimestampNormalization"/> covers the columns a raw
/// DateTimeOffset bind could have poisoned, not every column that ever existed) raises
/// <c>check_violation</c>. Each column's validation is therefore caught on its own and logged as a
/// warning, leaving that one constraint <c>NOT VALID</c> — enforcing new writes, not vouching for
/// old rows — while the other 131 validate normally. A single unfixable row must not wedge the
/// boot, and must not cost the whole instance its constraints.</para>
///
/// <para>A constraint left <c>NOT VALID</c> by an earlier boot is re-validated on the next one, so
/// an operator who repairs the offending row gets the constraint proven without a migration or a
/// ledger reset; the repeated scan is the ongoing cost, and the repeated warning is the signal that
/// something still needs repairing.</para>
///
/// <para><b>Release sequencing is a precondition no code can check.</b> A <c>NOT VALID</c>
/// constraint still rejects NEW writes, including the ones the OLD binary makes while both slots
/// serve the same database during a blue-green cutover. The retrofit is therefore only safe in a
/// release whose immediate predecessor already writes canonical timestamps on every path — notably
/// <c>package_versions.published_at</c>, <c>packages.upstream_latest_published_at</c>, and
/// <c>cache_artifact.published_at</c>, which the hosted-publish and proxy-first-fetch paths write.
/// Nothing in the schema records which binaries have written to a given database, so this cannot be
/// self-gating; it is a release-management decision. See the <c>Schema.pg.sql</c> header.</para>
/// </summary>
public sealed partial class SchemaInitializer
{
    /// <summary>
    /// Adds and validates the canonical-timestamp CHECK on every temporal column
    /// <paramref name="schemaSql"/> declares one for. No-op on SQLite. Called from
    /// <c>ApplySchemaAsync</c>, which already holds the cross-process migration lock, so no
    /// additional serialization is needed.
    /// </summary>
    internal async Task RetrofitTemporalChecksAsync(DbConnection conn, string schemaSql)
    {
        if (_db.Provider != DbProvider.Postgres)
        {
            return;
        }

        foreach (var (table, column) in DeclaredTemporalCheckColumns(schemaSql))
        {
            await EnsureTemporalCheckAsync(conn, table, column);
        }
    }

    /// <summary>
    /// Every <c>(table, column)</c> whose <c>CREATE TABLE</c> declaration in
    /// <paramref name="schemaSql"/> carries the exact <see cref="TemporalCheckPredicate.ForPostgres"/>
    /// text. Matching on the literal rather than on the column's name is deliberate: the retrofit
    /// then constrains precisely the set a fresh install constrains, never a superset inferred from
    /// a naming convention.
    /// internal so a test can assert the derived set against the schema file directly.
    /// </summary>
    internal static List<(string Table, string Column)> DeclaredTemporalCheckColumns(string schemaSql) =>
        SchemaSqlParser.ParseTableDefinitions(schemaSql)
            .SelectMany(entry => entry.Value.Columns
                .Where(column => column.Declaration.Contains(
                    TemporalCheckPredicate.ForPostgres(column.Name), StringComparison.Ordinal))
                .Select(column => (Table: entry.Key, column.Name)))
            .ToList();

    private async Task EnsureTemporalCheckAsync(DbConnection conn, string table, string column)
    {
        // Postgres's own auto-generated name for the unnamed inline CHECK in Schema.pg.sql's
        // CREATE TABLE block. Reusing it is what makes a retrofitted database and a fresh install
        // produce the identical catalogue object rather than two constraints under different names
        // that a later migration or a shape comparison would have to reconcile.
        string constraintName = table + "_" + column + "_check";

        // NULL = no such constraint; false = present but NOT VALID (a previous boot added it and
        // could not prove it); true = present and proven, which is the fresh-install steady state.
        // xtenant: reads the Postgres system catalogue, not application data — there is no tenant
        // column to filter on.
        bool? validated = await conn.ExecuteScalarAsync<bool?>(
            """
            SELECT c.convalidated
            FROM pg_constraint c
            JOIN pg_class t ON t.oid = c.conrelid
            JOIN pg_namespace n ON n.oid = t.relnamespace
            WHERE c.contype = 'c'
              AND c.conname = @constraintName
              AND t.relname = @table
              AND n.nspname = current_schema()
            """,
            new { constraintName, table });

        if (validated == true)
        {
            return;
        }

        // Sonar's engine mis-models Dapper's nullable scalar return and reads this branch as
        // dead; `validated` is `null` exactly when ExecuteScalarAsync<bool?> found no matching
        // row, which is the constraint-absent path this branch exists to handle.
#pragma warning disable S2583
        if (validated is null)
        {
            // rawsql: table, column, and constraintName are all structurally derived from the fixed
            // embedded Schema.pg.sql text this same boot applied, and the predicate comes from
            // TemporalCheckPredicate — none of it is caller-supplied, and Postgres has no parameter
            // form for a DDL identifier or a constraint body.
            await conn.ExecuteAsync(
                $"ALTER TABLE {table} ADD CONSTRAINT {constraintName} " +
                $"{TemporalCheckPredicate.ForPostgres(column)} NOT VALID");
        }
#pragma warning restore S2583

        try
        {
            // rawsql: see above — identifiers derived from the embedded schema text.
            await conn.ExecuteAsync($"ALTER TABLE {table} VALIDATE CONSTRAINT {constraintName}");
        }
        catch (PostgresException ex) when (ex.SqlState == PostgresErrorCodes.CheckViolation)
        {
            // One column's existing rows do not all satisfy the canonical shape. The constraint
            // stays in place and NOT VALID: every new write to this column is still rejected if it
            // is non-canonical, only the pre-existing rows are unvouched-for. Logged rather than
            // rethrown so the remaining columns are still retrofitted and the instance still boots
            // — and re-attempted on the next boot, so repairing the row is all an operator needs to
            // do to get the constraint proven.
            _logger.LogWarning(
                "Constraint {Constraint} on {Table}.{Column} could not be validated: existing rows " +
                "hold a non-canonical timestamp shape ({SqlState}). The constraint remains in place " +
                "but NOT VALID — new writes are still rejected if non-canonical, existing rows are " +
                "left as they are. Repair those rows to have the next boot validate it.",
                constraintName, table, column, ex.SqlState);
        }
    }
}
