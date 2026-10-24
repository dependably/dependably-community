using System.Data.Common;
using Dapper;

namespace Dependably.Infrastructure.OciScan;

/// <summary>
/// Writes a scan result's rows as multi-row <c>INSERT … VALUES (…), (…)</c> statements rather than
/// one statement per row, so a large result holds the database's writer for a bounded number of
/// round trips. Every value is a bound parameter; only generated <c>@column_row</c> placeholder
/// names are spliced into the statement.
/// </summary>
internal static class OciScanMultiRowInsert
{
    /// <summary>
    /// Bound parameters per statement. Well inside SQLite's variable limit (32,766) and Postgres's
    /// (65,535), so one statement is never refused for its size on either provider.
    /// </summary>
    internal const int MaxParametersPerStatement = 4_000;

    /// <summary>
    /// Inserts <paramref name="rows"/> through <paramref name="statement"/>, whose <c>{rows}</c>
    /// token stands for the VALUES list. Each row holds one value per entry of
    /// <paramref name="columns"/>, in the statement's column order.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "S2077:Formatting SQL queries is security-sensitive",
        Justification = "The statement is a compile-time constant; only generated @name placeholders are spliced into "
                        + "its VALUES list, and every value is bound.")]
    internal static async Task ExecuteAsync(
        DbConnection conn, DbTransaction tx, string statement, IReadOnlyList<string> columns,
        IReadOnlyList<object?[]> rows)
    {
        int perStatement = Math.Max(1, MaxParametersPerStatement / columns.Count);
        foreach (object?[][] batch in rows.Chunk(perStatement))
        {
            DynamicParameters parameters = new();
            string[] tuples = new string[batch.Length];
            for (int r = 0; r < batch.Length; r++)
            {
                string[] names = new string[columns.Count];
                for (int c = 0; c < columns.Count; c++)
                {
                    string name = columns[c] + "_" + r;
                    names[c] = "@" + name;
                    parameters.Add(name, batch[r][c]);
                }

                tuples[r] = "(" + string.Join(", ", names) + ")";
            }

            await conn.ExecuteAsync(statement.Replace("{rows}", string.Join(",\n", tuples)), parameters, tx);
        }
    }
}
