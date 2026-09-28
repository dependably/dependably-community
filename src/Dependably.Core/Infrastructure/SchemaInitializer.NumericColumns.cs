using System.Data.Common;
using Dapper;

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

    // Widens each column still at its narrow type. Idempotent per column — one already wide (a
    // fresh install, or a retry after a partial run) is skipped — and a no-op on SQLite. Each type
    // change rewrites the table, so the pending columns of one table go in a single ALTER TABLE (one
    // rewrite per table, not per column), and the migration runs non-transactionally so each table's
    // ACCESS EXCLUSIVE lock is released as soon as that table is done rather than held for the whole
    // pass while a blue-green peer is serving. RunOnceAsync drops the views before the body runs,
    // since Postgres refuses to retype a column a view reads, and EnsureViewsAsync recreates them
    // after the migrations. A value already stored as float4 keeps its float4 approximation; the
    // next write of that setting stores it exactly.
    private async Task WidenPostgresNumericColumnsAsync(DbConnection conn)
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
            await conn.ExecuteAsync($"ALTER TABLE {table.Key} {string.Join(", ", pending)}");
        }
    }
}
