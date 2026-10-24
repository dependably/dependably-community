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
    // pass while a blue-green peer is serving. The migration declares dropsViews, so RunOnceAsync drops the views before the body runs,
    // since Postgres refuses to retype a column a view reads, and EnsureViewsAsync recreates them
    // after the migrations. A value already stored as float4 keeps its float4 approximation; the
    // next write of that setting stores it exactly.
    //
    // The lock_timeout bound covers each ALTER attempt and nothing else. An ALTER queued behind a
    // long-running query holds its place in the lock queue, and every later query on that table
    // queues behind the ALTER, so an unbounded wait stalls the whole table for as long as the
    // blocker runs; with the bound, the ALTER gives up (SQLSTATE 55P03), steps out of the queue,
    // backs off and retries. Exhausting the retry budget fails startup with the table named; no
    // ledger row is written, so the next boot re-probes each column and resumes where this one
    // stopped. The catalogue probes run before the bound is set, because only the ALTER is retried
    // on 55P03: a probe that hit the bound would fail startup on a momentary catalogue lock
    // conflict the retry policy exists to ride out. lock_timeout bounds lock waits only, never the
    // work: it governs every lock the ALTER waits for (the table, its indexes, the catalogue rows
    // it rewrites), not how long the rewrite runs. The command timeout is lifted for the ALTER
    // itself, because rewriting a large table and rebuilding its indexes legitimately takes longer
    // than the client default. lock_timeout is
    // reset after every attempt, since the same connection carries on to the remaining migrations,
    // the views and row-level security. On the failure path the RESET is guarded, so a connection
    // the ALTER already broke never masks the ALTER's own exception.
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "S2077:Formatting SQL queries is security-sensitive",
        Justification = "The DDL identifiers and bodies derive from the embedded schema text this boot applied or from a "
                        + "private constant array; none is caller input, and Postgres cannot bind a DDL identifier.")]
    internal async Task WidenPostgresNumericColumnsAsync(DbConnection conn)
    {
        if (_db.Provider != DbProvider.Postgres)
        {
            return;
        }

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
            await AlterWithLockRetryAsync(
                conn, table.Key, $"ALTER TABLE {table.Key} {string.Join(", ", pending)}",
                "widen_postgres_numeric_columns", WidenLockRetry, failOnExhaustion: true);
        }
    }


    // Per-statement lock-retry budget for the constraint retrofits' ADD and VALIDATE. Each statement
    // is metadata-only (or a read-only scan), so the budget is smaller than the widening's. It bounds
    // one blocked table; what bounds the whole boot is the shared RetrofitPass deadline and its
    // table skip set, so a table (or a referenced table such as orgs) that stays locked is paid for
    // once rather than once per constraint.
    internal LockRetryPolicy ConstraintLockRetry { get; init; } = new(
        TimeSpan.FromSeconds(5),
        [TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(4)]);

    // One statement attempt under the session's lock_timeout (and, for a scan, statement_timeout),
    // both reset before returning. The command has no client timeout: the server-side settings are
    // the only bounds, and the caller chooses them.
    private async Task AlterBoundedAsync(
        DbConnection conn, string sql, string operation, TimeSpan lockTimeout, TimeSpan? statementTimeout)
    {
        await conn.ExecuteAsync(
            "SELECT set_config('lock_timeout', @value, false)",
            new { value = $"{(int)lockTimeout.TotalMilliseconds}ms" });
        if (statementTimeout is { } statement)
        {
            await conn.ExecuteAsync(
                "SELECT set_config('statement_timeout', @value, false)",
                new { value = $"{(int)statement.TotalMilliseconds}ms" });
        }

        try
        {
            await conn.ExecuteAsync(new CommandDefinition(sql, commandTimeout: 0));
        }
        catch
        {
            // Restore the session on the failure path too, but never let the RESET's own failure — a
            // connection the statement already broke — replace the exception that names the table and cause.
            try
            {
                await ResetTimeoutsAsync(conn, statementTimeout is not null);
            }
            catch (DbException resetEx)
            {
                _logger.LogWarning(resetEx, "Schema step {Operation} could not reset lock_timeout after a failure; the original error follows.", operation);
            }

            throw;
        }

        // Success path: a failed RESET here is a real fault (the connection carries on to the remaining
        // migrations, the views and row-level security), so it propagates.
        await ResetTimeoutsAsync(conn, statementTimeout is not null);
    }

    private static async Task ResetTimeoutsAsync(DbConnection conn, bool statementTimeoutSet)
    {
        await conn.ExecuteAsync("RESET lock_timeout");
        if (statementTimeoutSet)
        {
            await conn.ExecuteAsync("RESET statement_timeout");
        }
    }

    // Runs a statement under a bounded lock wait, retrying lock_not_available with TimeProvider back-off.
    // With failOnExhaustion the exhausted budget rethrows; otherwise it logs a warning and returns
    // LockExhausted, for a best-effort step that is re-attempted on the next boot. When a pass is given,
    // its deadline caps every lock wait and the statement timeout, and a spent deadline returns
    // DeadlineReached without running (or retrying) the statement.
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Major Code Smell", "S107:Methods should not have too many parameters",
        Justification = "Boot-time lock-retry state machine for DDL; splitting the attempt, deadline and exhaustion arms "
                        + "would scatter the invariants that keep a locked table from stalling startup.")]
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Critical Code Smell", "S3776:Cognitive Complexity of methods should not be too high",
        Justification = "Boot-time lock-retry state machine for DDL; splitting the attempt, deadline and exhaustion arms "
                        + "would scatter the invariants that keep a locked table from stalling startup.")]
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Critical Code Smell", "S134:Control flow statements should not be nested too deeply",
        Justification = "Boot-time lock-retry state machine for DDL; splitting the attempt, deadline and exhaustion arms "
                        + "would scatter the invariants that keep a locked table from stalling startup.")]
    private async Task<LockRetryOutcome> AlterWithLockRetryAsync(
        DbConnection conn,
        string table,
        string sql,
        string operation,
        LockRetryPolicy policy,
        bool failOnExhaustion,
        RetrofitPass? pass = null,
        TimeSpan? statementTimeout = null)
    {
        int attempts = policy.Backoff.Count + 1;
        for (int attempt = 0; ; attempt++)
        {
            if (pass is { Expired: true })
            {
                return LockRetryOutcome.DeadlineReached;
            }

            var lockTimeout = Capped(policy.LockTimeout, pass);
            var statement = statementTimeout is { } cap ? Capped(cap, pass) : (TimeSpan?)null;
            try
            {
                await AlterBoundedAsync(conn, sql, operation, lockTimeout, statement);
                return LockRetryOutcome.Ran;
            }
            catch (PostgresException ex) when (ex.SqlState == PostgresErrorCodes.LockNotAvailable)
            {
                if (pass is { Expired: true })
                {
                    return LockRetryOutcome.DeadlineReached;
                }

                if (attempt >= policy.Backoff.Count)
                {
                    if (!failOnExhaustion)
                    {
                        _logger.LogWarning(
                            ex,
                            "Schema step {Operation} could not lock table {Table} after {Attempts} attempts; "
                            + "another session holds a conflicting lock. The step is skipped, any constraint it "
                            + "concerns is left absent or NOT VALID, and it is re-attempted on the next boot.",
                            operation, table, attempts);
                        return LockRetryOutcome.LockExhausted;
                    }

                    _logger.LogError(
                        ex,
                        "Schema migration {Operation} could not lock table {Table} after {Attempts} attempts; "
                        + "another session holds a conflicting lock. Find the holders with "
                        + "SELECT l.pid, l.mode, a.state, a.query FROM pg_locks l JOIN pg_stat_activity a USING (pid) "
                        + "WHERE l.relation = '<table>'::regclass (or pg_blocking_pids(pid) against a waiting ALTER), "
                        + "then restart once they have finished.",
                        operation, table, attempts);
                    throw;
                }

                var delay = policy.Backoff[attempt];
                _logger.LogWarning(
                    "Schema step {Operation} could not lock table {Table} within {LockTimeout} "
                    + "(attempt {Attempt} of {Attempts}); retrying in {Delay}.",
                    operation, table, lockTimeout, attempt + 1, attempts, delay);
                await Task.Delay(delay, _time, CancellationToken.None);
            }
        }
    }

    // min(requested, what the pass has left), never below 1 ms: a zero timeout means "no limit".
    private static TimeSpan Capped(TimeSpan requested, RetrofitPass? pass)
    {
        var capped = pass is null || requested < pass.Remaining ? requested : pass.Remaining;
        return capped < TimeSpan.FromMilliseconds(1) ? TimeSpan.FromMilliseconds(1) : capped;
    }
}
