using System.Data.Common;
using Dapper;
using Npgsql;

namespace Dependably.Infrastructure;

public sealed partial class SchemaInitializer
{
    // Columns Schema.pg.sql once declared with a type narrower on Postgres than on SQLite, where
    // INTEGER is 64-bit and REAL is 8-byte. On Postgres INTEGER is int4, so a per-org upload cap
    // above 2 GiB — or an OCI layer, hosted file or SBOM document that large — fails with 22003
    // "integer out of range"; REAL is float4, so a stored EPSS or CVSS threshold reads back as a
    // nearby value and a gate comparing against it can land on the wrong side of the boundary.
    private static readonly (string Table, string Column, string FromType, string ToType)[] PostgresNarrowNumericColumns =
    [
        ("org_settings", "max_upload_bytes", "integer", "BIGINT"),
        ("org_settings", "max_upload_bytes_pypi", "integer", "BIGINT"),
        ("org_settings", "max_upload_bytes_npm", "integer", "BIGINT"),
        ("org_settings", "max_upload_bytes_nuget", "integer", "BIGINT"),
        ("org_settings", "max_upload_bytes_maven", "integer", "BIGINT"),
        ("org_settings", "max_upload_bytes_rpm", "integer", "BIGINT"),
        ("org_settings", "max_upload_bytes_oci", "integer", "BIGINT"),
        ("org_settings", "max_upload_bytes_cargo", "integer", "BIGINT"),
        ("org_settings", "max_upload_bytes_hex", "integer", "BIGINT"),
        ("package_versions", "size_bytes", "integer", "BIGINT"),
        ("rpm_metadata", "installed_size", "integer", "BIGINT"),
        ("rpm_metadata", "archive_size", "integer", "BIGINT"),
        ("maven_version_files", "size_bytes", "integer", "BIGINT"),
        ("oci_blobs", "size_bytes", "integer", "BIGINT"),
        ("oci_uploads", "received_bytes", "integer", "BIGINT"),
        ("project_documents", "size_bytes", "integer", "BIGINT"),
        ("org_settings", "max_osv_score_tolerance", "real", "DOUBLE PRECISION"),
        ("org_settings", "max_epss_tolerance", "real", "DOUBLE PRECISION"),
        ("org_settings", "max_epss_percentile_tolerance", "real", "DOUBLE PRECISION"),
        ("vulnerabilities", "cvss_score", "real", "DOUBLE PRECISION"),
        ("vulnerabilities", "epss_score", "real", "DOUBLE PRECISION"),
        ("vulnerabilities", "nvd_score", "real", "DOUBLE PRECISION"),
        ("vulnerabilities", "epss_percentile", "real", "DOUBLE PRECISION"),
        ("vulnerabilities", "cvelist_cvss_score", "real", "DOUBLE PRECISION"),
        ("project_vuln_analysis", "security_severity", "real", "DOUBLE PRECISION"),
    ];

    // How long each table's ALTER waits for its lock before giving up, and the back-off between
    // attempts. The whole budget (lock timeout per attempt plus every back-off) stays well under
    // MigrationLockMaxWait, so a peer replica polling the migration lock does not time out first.
    internal sealed record LockRetryPolicy(TimeSpan LockTimeout, IReadOnlyList<TimeSpan> Backoff)
    {
        public static LockRetryPolicy Default { get; } = new(
            TimeSpan.FromSeconds(5),
            [
                TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(4), TimeSpan.FromSeconds(8),
                TimeSpan.FromSeconds(15), TimeSpan.FromSeconds(15), TimeSpan.FromSeconds(15), TimeSpan.FromSeconds(15),
                TimeSpan.FromSeconds(15), TimeSpan.FromSeconds(15), TimeSpan.FromSeconds(15),
            ]);
    }

    // Test seam: production always runs the default policy; tests shrink it to keep a blocked
    // table's retry budget measured in milliseconds.
    internal LockRetryPolicy WidenLockRetry { get; init; } = LockRetryPolicy.Default;

    // Widens each column still at its narrow type. Idempotent per column — one already wide (a
    // fresh install, or a retry after a partial run) is skipped — and a no-op on SQLite. Each type
    // change rewrites the table, so the pending columns of one table go in a single ALTER TABLE (one
    // rewrite per table, not per column), and the migration runs non-transactionally so each table's
    // ACCESS EXCLUSIVE lock is released as soon as that table is done rather than held for the whole
    // pass while a blue-green peer is serving. RunOnceAsync drops the views before the body runs,
    // since Postgres refuses to retype a column a view reads, and EnsureViewsAsync recreates them
    // after the migrations. A value already stored as float4 keeps its float4 approximation; the
    // next write of that setting stores it exactly.
    //
    // Lock acquisition is bounded by the session's lock_timeout. An ALTER queued behind a
    // long-running query holds its place in the lock queue, and every later query on that table
    // queues behind the ALTER, so an unbounded wait stalls the whole table for as long as the
    // blocker runs; with the bound, the ALTER gives up (SQLSTATE 55P03), steps out of the queue,
    // backs off and retries. Exhausting the retry budget fails startup with the table named; no
    // ledger row is written, so the next boot re-probes each column and resumes where this one
    // stopped. Only lock acquisition is bounded: the command timeout is lifted for the ALTER itself,
    // because rewriting a large table and rebuilding its indexes legitimately takes longer than the
    // client default. lock_timeout is reset afterwards, since the same connection carries on to the
    // remaining migrations, the views and row-level security. On the failure path the RESET is
    // guarded, so a connection the ALTER already broke never masks the ALTER's own exception.
    internal async Task WidenPostgresNumericColumnsAsync(DbConnection conn)
    {
        if (_db.Provider != DbProvider.Postgres)
        {
            return;
        }

        await conn.ExecuteAsync(
            "SELECT set_config('lock_timeout', @value, false)",
            new { value = $"{(int)WidenLockRetry.LockTimeout.TotalMilliseconds}ms" });
        try
        {
            foreach (var table in PostgresNarrowNumericColumns.GroupBy(c => c.Table))
            {
                var pending = new List<string>();
                foreach ((_, string column, string fromType, string toType) in table)
                {
                    string? type = await conn.ExecuteScalarAsync<string?>(
                        """
                        SELECT data_type FROM information_schema.columns
                        WHERE table_schema = current_schema() AND table_name = @table AND column_name = @column
                        """,
                        new { table = table.Key, column });
                    if (type == fromType)
                    {
                        pending.Add($"ALTER COLUMN {column} TYPE {toType}");
                    }
                }

                if (pending.Count == 0)
                {
                    continue;
                }

                // rawsql: table, column and type come from PostgresNarrowNumericColumns, a private compile-time constant array.
                await AlterWithLockRetryAsync(conn, table.Key, $"ALTER TABLE {table.Key} {string.Join(", ", pending)}");
            }
        }
        catch
        {
            // Restore the session on the failure path too, but never let the RESET's own failure — a
            // connection the ALTER already broke — replace the exception that names the table and cause.
            try
            {
                await conn.ExecuteAsync("RESET lock_timeout");
            }
            catch (DbException resetEx)
            {
                _logger.LogWarning(resetEx, "Schema migration widen_postgres_numeric_columns could not reset lock_timeout after a failure; the original error follows.");
            }

            throw;
        }

        // Success path: a failed RESET here is a real fault (the connection carries on to the remaining
        // migrations, the views and row-level security), so it propagates.
        await conn.ExecuteAsync("RESET lock_timeout");
    }

    private async Task AlterWithLockRetryAsync(DbConnection conn, string table, string sql)
    {
        int attempts = WidenLockRetry.Backoff.Count + 1;
        for (int attempt = 0; ; attempt++)
        {
            try
            {
                await conn.ExecuteAsync(new CommandDefinition(sql, commandTimeout: 0));
                return;
            }
            catch (PostgresException ex) when (ex.SqlState == PostgresErrorCodes.LockNotAvailable)
            {
                if (attempt >= WidenLockRetry.Backoff.Count)
                {
                    _logger.LogError(
                        ex,
                        "Schema migration widen_postgres_numeric_columns could not lock table {Table} after {Attempts} attempts; "
                        + "another session holds a conflicting lock. Find the holders with "
                        + "SELECT l.pid, l.mode, a.state, a.query FROM pg_locks l JOIN pg_stat_activity a USING (pid) "
                        + "WHERE l.relation = '<table>'::regclass (or pg_blocking_pids(pid) against a waiting ALTER), "
                        + "then restart once they have finished.",
                        table, attempts);
                    throw;
                }

                var delay = WidenLockRetry.Backoff[attempt];
                _logger.LogWarning(
                    "Schema migration widen_postgres_numeric_columns could not lock table {Table} within {LockTimeout} "
                    + "(attempt {Attempt} of {Attempts}); retrying in {Delay}.",
                    table, WidenLockRetry.LockTimeout, attempt + 1, attempts, delay);
                await Task.Delay(delay, _time, CancellationToken.None);
            }
        }
    }
}
