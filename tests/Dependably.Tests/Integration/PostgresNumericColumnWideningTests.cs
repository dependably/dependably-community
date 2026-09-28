using Dapper;
using Dependably.Infrastructure;

namespace Dependably.Tests.Integration;

/// <summary>
/// Byte counts and caps must hold values over 2 GiB, and score thresholds must round-trip exactly, on
/// Postgres — where INTEGER is 32-bit and REAL is 4-byte. Pins both the fresh-install shape and the
/// migration that widens an existing database's columns.
/// </summary>
[Trait("Category", "SchemaPostgres")]
[Collection("LivePostgres")]
public sealed class PostgresNumericColumnWideningTests
{
    private const long FiveGiB = 5L * 1024 * 1024 * 1024;

    private static string ConnectionString =>
        Environment.GetEnvironmentVariable("TEST_POSTGRES_CONNECTION")
        ?? throw new InvalidOperationException(
            "TEST_POSTGRES_CONNECTION must be set to run Category=SchemaPostgres tests.");

    [Fact]
    public async Task FreshInstall_StoresValuesOver2GiB_AndThresholdsExactly()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        await new SchemaInitializer(pg.Store).InitializeAsync();
        await using var conn = await pg.Store.OpenAsync();

        await conn.ExecuteAsync(
            """
            INSERT INTO orgs (id, slug) VALUES ('o1', 'acme');
            INSERT INTO org_settings (org_id, max_upload_bytes_oci, max_epss_tolerance) VALUES ('o1', @big, 0.35)
                ON CONFLICT (org_id) DO UPDATE SET max_upload_bytes_oci = @big, max_epss_tolerance = 0.35;
            INSERT INTO oci_blobs (digest, org_id, media_type, size_bytes, blob_key)
                VALUES ('sha256:big', 'o1', 'application/octet-stream', @big, 'k');
            """,
            new { big = FiveGiB });

        Assert.Equal(FiveGiB, await conn.ExecuteScalarAsync<long>("SELECT max_upload_bytes_oci FROM org_settings WHERE org_id = 'o1'"));
        Assert.Equal(FiveGiB, await conn.ExecuteScalarAsync<long>("SELECT size_bytes FROM oci_blobs WHERE digest = 'sha256:big'"));
        Assert.Equal(0.35, await conn.ExecuteScalarAsync<double>("SELECT max_epss_tolerance FROM org_settings WHERE org_id = 'o1'"));
    }

    [Fact]
    public async Task ExistingDatabase_WithIntegerColumns_IsWidenedOnUpgrade()
    {
        await using var pg = await LivePostgresReset.FreshAsync(ConnectionString);
        await new SchemaInitializer(pg.Store).InitializeAsync();
        await using var conn = await pg.Store.OpenAsync();

        // Recreate the pre-widening shape: the columns as int4 and the migration not yet ledgered.
        await conn.ExecuteAsync(
            """
            DO $$
            DECLARE v record;
            BEGIN
              FOR v IN SELECT table_name FROM information_schema.views WHERE table_schema = current_schema() LOOP
                EXECUTE format('DROP VIEW IF EXISTS %I CASCADE', v.table_name);
              END LOOP;
            END $$;
            ALTER TABLE org_settings ALTER COLUMN max_upload_bytes_oci TYPE INTEGER;
            ALTER TABLE oci_blobs ALTER COLUMN size_bytes TYPE INTEGER;
            ALTER TABLE org_settings ALTER COLUMN max_epss_tolerance TYPE REAL;
            DELETE FROM _applied_migrations WHERE name = 'widen_postgres_numeric_columns';
            """);
        Assert.Equal("integer", await ColumnTypeAsync(conn, "oci_blobs", "size_bytes"));

        await new SchemaInitializer(pg.Store).InitializeAsync();

        Assert.Equal("bigint", await ColumnTypeAsync(conn, "oci_blobs", "size_bytes"));
        Assert.Equal("bigint", await ColumnTypeAsync(conn, "org_settings", "max_upload_bytes_oci"));
        Assert.Equal("double precision", await ColumnTypeAsync(conn, "org_settings", "max_epss_tolerance"));
        Assert.Equal(1L, await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM information_schema.views WHERE table_schema = current_schema() AND table_name = 'org_storage_bytes'"));
    }

    private static Task<string?> ColumnTypeAsync(System.Data.Common.DbConnection conn, string table, string column) =>
        conn.ExecuteScalarAsync<string?>(
            """
            SELECT data_type FROM information_schema.columns
            WHERE table_schema = current_schema() AND table_name = @table AND column_name = @column
            """,
            new { table, column });
}
