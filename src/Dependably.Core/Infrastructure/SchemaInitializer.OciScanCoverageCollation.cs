using System.Data.Common;
using Dapper;

namespace Dependably.Infrastructure;

public sealed partial class SchemaInitializer
{
    // Brings oci_scan_coverage.matched_at to the COLLATE "C" Schema.pg.sql declares for every indexed
    // temporal column (idx_oci_scan_coverage_org_matched keys on it). A database whose column carries
    // the default collation converges on boot; CREATE TABLE IF NOT EXISTS never revisits an existing
    // table, so nothing else would correct it.
    //
    // The schema file's rule is that an indexed temporal column is not re-collated in place, because
    // the ALTER rewrites the table and its indexes under ACCESS EXCLUSIVE. This column is the one
    // exception. The table is small — one row per scanned platform, per image, per org — so the
    // rewrite is short; the wait for the lock is bounded by ConstraintLockRetry (5 s per attempt,
    // four attempts) and is not fatal; and a brief stall of concurrent OCI scan reads and writes,
    // including those of another replica serving the same database, is accepted. The alternative, a
    // maintenance-window runbook entry, leaves the index miscollated until an operator runs it.
    //
    // Every boot, probe-gated, and best effort: a database already in the canonical shape pays one
    // catalogue read, and a lock that cannot be had within the retry budget skips the change with a
    // warning for the next boot to retry rather than failing startup. No-op on SQLite, whose default
    // TEXT collation is already byte order.
    private async Task ConvergeOciScanCoverageMatchedAtCollationAsync(DbConnection conn)
    {
        if (_db.Provider != DbProvider.Postgres)
        {
            return;
        }

        string? collation = await conn.QueryFirstOrDefaultAsync<string?>(
            """
            SELECT co.collname
            FROM pg_attribute a
            JOIN pg_class t ON t.oid = a.attrelid
            JOIN pg_namespace n ON n.oid = t.relnamespace
            JOIN pg_collation co ON co.oid = a.attcollation
            WHERE n.nspname = current_schema()
              AND t.relname = 'oci_scan_coverage'
              AND a.attname = 'matched_at'
              AND NOT a.attisdropped
            """);
        if (collation is null || string.Equals(collation, "C", StringComparison.Ordinal))
        {
            return;
        }

        await AlterWithLockRetryAsync(
            conn, "oci_scan_coverage",
            "ALTER TABLE oci_scan_coverage ALTER COLUMN matched_at TYPE TEXT COLLATE \"C\"",
            "collate_oci_scan_coverage_matched_at", ConstraintLockRetry, failOnExhaustion: false);
    }
}
