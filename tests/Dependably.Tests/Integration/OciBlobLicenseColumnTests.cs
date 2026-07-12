using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Integration;

/// <summary>
/// Additive-migration coverage for the OCI image-license columns on <c>oci_blobs</c>
/// (<c>config_digest</c> / <c>license_spdx</c> / <c>license_checked_at</c>) plus the
/// <c>idx_oci_blobs_org_config_digest</c> index. The fresh-install path (full CREATE TABLE)
/// and the upgraded-database path (a table predating the columns, repaired by the additive
/// ALTERs) must both leave the three nullable columns and the index present, and re-running the
/// initializer must be a no-op.
/// </summary>
[Trait("Category", "Integration")]
public sealed class OciBlobLicenseColumnTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public Task InitializeAsync() => Task.CompletedTask;
    public async Task DisposeAsync() => await _db.DisposeAsync();

    [Fact]
    public async Task FreshInstall_HasNullableColumnsAndIndex()
    {
        await new SchemaInitializer(_db).InitializeAsync();

        await using var verify = await _db.OpenAsync();
        await AssertColumnsAndIndexPresentAsync(verify);
    }

    [Fact]
    public async Task UpgradedDatabase_MissingColumns_AdditiveMigrationsRepairThem()
    {
        // Fresh install gives us a full schema, then we regress oci_blobs to its pre-column shape
        // (columns are not part of any PK/UNIQUE, so SQLite DROP COLUMN succeeds) — the exact
        // state an upgraded database is in before the additive ALTERs run.
        await new SchemaInitializer(_db).InitializeAsync();
        await using (var regress = await _db.OpenAsync())
        {
            await regress.ExecuteAsync("DROP INDEX IF EXISTS idx_oci_blobs_org_config_digest");
            await regress.ExecuteAsync("ALTER TABLE oci_blobs DROP COLUMN license_checked_at");
            await regress.ExecuteAsync("ALTER TABLE oci_blobs DROP COLUMN license_spdx");
            await regress.ExecuteAsync("ALTER TABLE oci_blobs DROP COLUMN config_digest");
        }

        // Re-run: the additive migrations re-add the columns + index (they run every init).
        await new SchemaInitializer(_db).InitializeAsync();

        await using var verify = await _db.OpenAsync();
        await AssertColumnsAndIndexPresentAsync(verify);
    }

    [Fact]
    public async Task Initializer_RunTwice_IsIdempotent()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        var ex = await Record.ExceptionAsync(() => new SchemaInitializer(_db).InitializeAsync());
        Assert.Null(ex);

        await using var verify = await _db.OpenAsync();
        long spdxCols = await verify.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM pragma_table_info('oci_blobs') WHERE name = 'license_spdx'");
        Assert.Equal(1, spdxCols);

        // Nullable columns accept a row that omits them (fresh-install shape).
        await verify.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o-oci-lic', 'oci-lic')");
        await verify.ExecuteAsync("""
            INSERT INTO oci_blobs (digest, org_id, media_type, size_bytes, blob_key)
            VALUES ('sha256:abc', 'o-oci-lic', 'application/vnd.oci.image.manifest.v1+json', 10, 'k')
            """);
        var (configDigest, spdx, checkedAt) = await verify.QuerySingleAsync<(string? configDigest, string? spdx, string? checkedAt)>(
            "SELECT config_digest AS configDigest, license_spdx AS spdx, license_checked_at AS checkedAt " +
            "FROM oci_blobs WHERE org_id = 'o-oci-lic'");
        Assert.Null(configDigest);
        Assert.Null(spdx);
        Assert.Null(checkedAt);
    }

    private static async Task AssertColumnsAndIndexPresentAsync(System.Data.Common.DbConnection conn)
    {
        foreach (string column in new[] { "config_digest", "license_spdx", "license_checked_at" })
        {
            var (name, notnull) = await conn.QuerySingleOrDefaultAsync<(string name, int notnull)>(
                "SELECT name, \"notnull\" FROM pragma_table_info('oci_blobs') WHERE name = @column",
                new { column });
            Assert.Equal(column, name);
            Assert.Equal(0, notnull); // nullable, no DEFAULT
        }

        string? indexName = await conn.QuerySingleOrDefaultAsync<string>(
            "SELECT name FROM sqlite_master WHERE type='index' AND name='idx_oci_blobs_org_config_digest'");
        Assert.Equal("idx_oci_blobs_org_config_digest", indexName);
    }
}
