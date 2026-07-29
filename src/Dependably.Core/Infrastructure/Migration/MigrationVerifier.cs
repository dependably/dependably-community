using System.Data.Common;
using System.Security.Cryptography;
using System.Text;

namespace Dependably.Infrastructure.Migration;

/// <summary>Per-table verification outcome: row counts plus an order-independent content digest.</summary>
public sealed record TableVerification(
    string Table,
    long SourceRows,
    long TargetRows,
    string SourceDigest,
    string TargetDigest)
{
    /// <summary>True when the target holds exactly the source's rows, value for value.</summary>
    public bool Ok => SourceRows == TargetRows && string.Equals(SourceDigest, TargetDigest, StringComparison.Ordinal);
}

/// <summary>The full verification result across every migrated table.</summary>
public sealed record MigrationVerificationReport(IReadOnlyList<TableVerification> Tables, IReadOnlyList<string> SkippedTables)
{
    /// <summary>
    /// Every compared table matched — and at least one table was actually compared. The count guard
    /// is load-bearing: a target with no schema at all skips every table, and an all-empty
    /// comparison would otherwise report success. A verifier that passes vacuously is worse than no
    /// verifier, because an operator acts on it.
    /// </summary>
    public bool Ok => Tables.Count > 0 && Tables.All(t => t.Ok);

    public IReadOnlyList<TableVerification> Failures => Tables.Where(t => !t.Ok).ToList();

    public long TotalSourceRows => Tables.Sum(t => t.SourceRows);

    public long TotalTargetRows => Tables.Sum(t => t.TargetRows);
}

/// <summary>
/// Compares a migrated Postgres database against the SQLite database it was copied from, table by
/// table, on both row count and content. It rebuilds the column plan from the two live catalogues,
/// so it runs standalone — an operator can verify a migration performed hours earlier, or re-verify
/// after a suspected incident, without re-running the copy.
///
/// <para>Content is compared through a digest rather than a row-by-row join because there is no
/// engine-independent ordering to join on: several tables have composite or opaque keys, and a
/// stable <c>ORDER BY</c> would itself have to be provider-branched. Each row is canonicalised to a
/// single string (via the same conversion the copy uses, so representation differences that are
/// correct — an ISO-8601 string landing in a <c>timestamptz</c> — do not register as drift), hashed,
/// and folded into the table digest with two order-independent operators: an XOR and a wrapping
/// sum. XOR alone would let an even number of identical differing rows cancel out; the sum and the
/// row count close that. A single changed byte in a single column changes the digest.</para>
/// </summary>
public static class MigrationVerifier
{
    // ASCII unit separator: a control character no canonical token contains, so two
    // different column splits can never render to the same row string.
    private const char FieldSeparator = '\u001F';

    /// <summary>
    /// Verifies every table in <paramref name="plan"/>. Tables absent from the target (dropped by a
    /// later release) are reported as skipped rather than failed.
    /// </summary>
    public static async Task<MigrationVerificationReport> VerifyAsync(
        DbConnection sqlite,
        DbConnection pg,
        MigrationTablePlan plan,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(plan);

        var results = new List<TableVerification>(plan.Tables.Count);
        var skipped = new List<string>();

        foreach (string table in plan.Tables)
        {
            var columnPlan = await MigrationColumnPlanner.BuildAsync(sqlite, pg, table, ct);
            if (columnPlan is null)
            {
                skipped.Add(table);
                continue;
            }

            var (sourceRows, sourceDigest) = await DigestSourceAsync(sqlite, columnPlan, ct);
            var (targetRows, targetDigest) = await DigestTargetAsync(pg, columnPlan, ct);
            results.Add(new TableVerification(table, sourceRows, targetRows, sourceDigest, targetDigest));
        }

        return new MigrationVerificationReport(results, skipped);
    }

    private static async Task<(long Rows, string Digest)> DigestSourceAsync(
        DbConnection sqlite, TableColumnPlan plan, CancellationToken ct)
    {
        await using var cmd = sqlite.CreateCommand();
        cmd.CommandText = SelectSql(plan);
        await using var reader = await cmd.ExecuteReaderAsync(ct);

        var accumulator = new DigestAccumulator();
        var builder = new StringBuilder();
        while (await reader.ReadAsync(ct))
        {
            builder.Clear();
            for (int i = 0; i < plan.Columns.Count; i++)
            {
                var column = plan.Columns[i];
                object? raw = await reader.IsDBNullAsync(i, ct) ? null : reader.GetValue(i);
                object? converted = PostgresValueConverter.ToPostgresValue(plan.Table, column, raw);
                builder.Append(PostgresValueConverter.Canonical(column.Kind, converted)).Append(FieldSeparator);
            }

            accumulator.Add(builder);
        }

        return accumulator.Result;
    }

    private static async Task<(long Rows, string Digest)> DigestTargetAsync(
        DbConnection pg, TableColumnPlan plan, CancellationToken ct)
    {
        await using var cmd = pg.CreateCommand();
        cmd.CommandText = SelectSql(plan);
        await using var reader = await cmd.ExecuteReaderAsync(ct);

        var accumulator = new DigestAccumulator();
        var builder = new StringBuilder();
        while (await reader.ReadAsync(ct))
        {
            builder.Clear();
            for (int i = 0; i < plan.Columns.Count; i++)
            {
                var column = plan.Columns[i];
                object? value = await reader.IsDBNullAsync(i, ct) ? null : reader.GetValue(i);
                builder.Append(PostgresValueConverter.Canonical(column.Kind, value)).Append(FieldSeparator);
            }

            accumulator.Add(builder);
        }

        return accumulator.Result;
    }

    /// <summary>
    /// The identical projection both engines are read through. Every spliced identifier is a
    /// catalogue-derived name already validated by <see cref="MigrationColumnPlanner.Quote"/>.
    /// </summary>
    // rawsql: table/column identifiers come from the live catalogue and are validated by
    // MigrationColumnPlanner.Quote; the statement carries no values and takes no parameters.
    // xtenant: whole-database verification of a SQLite → Postgres migration is cross-tenant by design.
    internal static string SelectSql(TableColumnPlan plan) =>
        $"SELECT {string.Join(", ", plan.Columns.Select(c => MigrationColumnPlanner.Quote(c.Name)))} " +
        $"FROM {MigrationColumnPlanner.Quote(plan.Table)}";

    /// <summary>
    /// Folds per-row hashes into one table digest with two order-independent operators, so the
    /// comparison never depends on the two engines returning rows in the same order.
    /// </summary>
    private sealed class DigestAccumulator
    {
        private readonly byte[] _hash = new byte[32];
        private ulong _xor;
        private ulong _sum;
        private long _rows;

        public void Add(StringBuilder row)
        {
            string text = row.ToString();
            byte[] buffer = Encoding.UTF8.GetBytes(text);
            SHA256.HashData(buffer, _hash);

            ulong value = BitConverter.ToUInt64(_hash, 0);
            _xor ^= value;
            unchecked
            {
                _sum += value;
            }

            _rows++;
        }

        public (long Rows, string Digest) Result => (_rows, $"{_xor:x16}:{_sum:x16}");
    }
}
