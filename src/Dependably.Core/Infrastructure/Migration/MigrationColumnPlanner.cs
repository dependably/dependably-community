using System.Data.Common;
using System.Text.RegularExpressions;
using Dapper;

namespace Dependably.Infrastructure.Migration;

/// <summary>
/// The columns of one table that the copy moves, in source order, each already resolved to the
/// Postgres storage class it lands in. The copy and the verification pass both build this from the
/// live catalogues, so a standalone verification run reads exactly the columns the copy wrote.
/// </summary>
public sealed record TableColumnPlan(string Table, IReadOnlyList<PostgresColumn> Columns);

/// <summary>
/// Resolves, per table, which columns are copied and what they become on the Postgres side.
/// Also owns identifier quoting: every identifier that reaches a SQL string is first proven to be a
/// catalogue-derived name matching <see cref="IdentifierRegex"/>, so the dynamically assembled
/// column lists carry no injection surface.
/// </summary>
public static partial class MigrationColumnPlanner
{
    /// <summary>
    /// The only shape an identifier may have to be spliced into a statement. Every table and column
    /// name in this path comes from <c>sqlite_master</c> / <c>information_schema</c> — never from a
    /// request or an operator argument — and is still checked against this before use.
    /// </summary>
    [GeneratedRegex("^[A-Za-z_][A-Za-z0-9_]*$")]
    private static partial Regex IdentifierRegex();

    /// <summary>Validates a catalogue-derived identifier and returns it double-quoted.</summary>
    public static string Quote(string identifier) =>
        string.IsNullOrEmpty(identifier) || !IdentifierRegex().IsMatch(identifier)
            ? throw new MetadataMigrationException(
                $"'{identifier}' is not a plain SQL identifier and will not be used to build a statement.")
            : "\"" + identifier + "\"";

    /// <summary>Reads a SQLite table's column names in declaration order.</summary>
    public static async Task<IReadOnlyList<string>> SqliteColumnsAsync(
        DbConnection sqlite, string table, CancellationToken ct = default)
    {
        // xtenant: SQLite catalogue introspection; pragma_table_info has no tenant column.
        var columns = await sqlite.QueryAsync<string>(new CommandDefinition(
            "SELECT name FROM pragma_table_info(@table) ORDER BY cid",
            new { table },
            cancellationToken: ct));
        return columns.ToList();
    }

    /// <summary>
    /// Reads a Postgres table's columns, resolved to their migration storage class. An empty result
    /// means the table does not exist in the target.
    /// </summary>
    public static async Task<IReadOnlyList<PostgresColumn>> PostgresColumnsAsync(
        DbConnection pg, string table, CancellationToken ct = default)
    {
        // xtenant: information_schema introspection of the target database; not a tenant-scoped read.
        var rows = await pg.QueryAsync<(string ColumnName, string DataType, string IsNullable)>(
            new CommandDefinition(
                """
                SELECT column_name AS ColumnName, data_type AS DataType, is_nullable AS IsNullable
                FROM information_schema.columns
                WHERE table_schema = 'public' AND table_name = @table
                ORDER BY ordinal_position
                """,
                new { table },
                cancellationToken: ct));

        return rows
            .Select(r => new PostgresColumn(
                r.ColumnName,
                PostgresValueConverter.ResolveKind(table, r.ColumnName, r.DataType),
                string.Equals(r.IsNullable, "YES", StringComparison.OrdinalIgnoreCase)))
            .ToList();
    }

    /// <summary>
    /// Builds the copy plan for one table. Returns <see langword="null"/> when the target has no
    /// such table — a source table the current release has already dropped, which the caller reports
    /// and skips rather than aborting a migration over data no code reads.
    /// </summary>
    /// <exception cref="MetadataMigrationException">
    /// The source has a column the target lacks. That means the target schema is older than the
    /// source's, and copying would silently drop a column's worth of data.
    /// </exception>
    public static async Task<TableColumnPlan?> BuildAsync(
        DbConnection sqlite, DbConnection pg, string table, CancellationToken ct = default)
    {
        var targetColumns = await PostgresColumnsAsync(pg, table, ct);
        if (targetColumns.Count == 0)
        {
            return null;
        }

        var targetByName = targetColumns.ToDictionary(c => c.Name, StringComparer.OrdinalIgnoreCase);
        var sourceColumns = await SqliteColumnsAsync(sqlite, table, ct);

        var missing = sourceColumns.Where(c => !targetByName.ContainsKey(c)).ToList();
        return missing.Count > 0
            ? throw new MetadataMigrationException(
                $"{table}: column(s) {string.Join(", ", missing)} exist in the SQLite source but not in " +
                $"the Postgres target. The target schema is older than the source's — upgrade both to " +
                $"the same release before migrating.")
            : new TableColumnPlan(table, sourceColumns.Select(c => targetByName[c]).ToList());
    }

    /// <summary>
    /// Target columns absent from the source. They take their Postgres defaults on copy; a NOT NULL
    /// column with no default fails the copy loudly rather than inventing a value.
    /// </summary>
    public static IReadOnlyList<string> TargetOnlyColumns(
        IReadOnlyList<PostgresColumn> targetColumns, IReadOnlyList<string> sourceColumns)
    {
        var source = new HashSet<string>(sourceColumns, StringComparer.OrdinalIgnoreCase);
        return targetColumns.Where(c => !source.Contains(c.Name)).Select(c => c.Name).ToList();
    }
}
