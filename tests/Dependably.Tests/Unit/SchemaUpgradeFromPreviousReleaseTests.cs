using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Compliance;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit;

/// <summary>
/// The upgrade path itself, end to end. Every other <c>Category=Schema</c> test applies the current
/// schema to an empty database — which is the ONE shape that cannot see an ordering fault between
/// the declarative schema file and the additive migration pass, because on a fresh database the
/// <c>CREATE TABLE</c> blocks put every column in place before anything else runs.
///
/// <para>These start from the previous release's <c>Schema.sql</c> — the shape every live database
/// booting this build actually has — and then run the real <see cref="SchemaInitializer"/>. That is
/// what makes them able to fail on a statement in <c>Schema.sql</c> that names a column only
/// <c>RunAdditiveMigrationsAsync</c> adds. On SQLite that failure is silent:
/// <c>Microsoft.Data.Sqlite</c> stops executing the batch at the failing statement and raises
/// nothing the initializer surfaces, so every table declared LATER in the file is simply never
/// created and initialization still reports success. The later-table assertions below are the
/// detector for that shape; a thrown exception is the Postgres shape and fails just as loudly.</para>
///
/// <para>A repository with no readable release tag has no upgrade path to check and passes — the
/// static <see cref="SchemaUpgradeOrderComplianceTests"/> gate covers the same hazard without
/// needing a database.</para>
/// </summary>
[Trait("Category", "Schema")]
public sealed class SchemaUpgradeFromPreviousReleaseTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    public Task InitializeAsync() => Task.CompletedTask;
    public async Task DisposeAsync() => await _db.DisposeAsync();


    [Fact]
    public async Task Initializing_APreviousReleaseDatabase_CreatesEveryTableAndTheBindingColumns()
    {
        var baseline = ResolveBaselineOrSkip();
        if (baseline is null)
        {
            return;
        }

        await ApplyBaselineSchemaAsync(baseline.SqliteSql);

        await new SchemaInitializer(_db).InitializeAsync();

        await using var conn = await _db.OpenAsync();

        // The truncation detector. Every table Schema.sql declares must exist after an upgrade
        // boot; a statement that fails part-way through the file takes every table declared after
        // it with it — instance_lock (the HA leader lock) and webhook_subscription (the per-org
        // webhook registry) are two of the thirteen sitting behind tenant_artifact_access — and
        // Microsoft.Data.Sqlite raises nothing the initializer surfaces, so the boot still reports
        // success. Asserted over the whole declared inventory rather than a hand-picked pair so it
        // keeps detecting the fault as tables are added, wherever in the file they land.
        var declared = SchemaSqlParser.ParseTables(
            await File.ReadAllTextAsync(SchemaTestPaths.SqliteSchema(SchemaTestPaths.SourceRoot())));
        var missing = new List<string>();
        foreach (string table in declared.Keys)
        {
            if (!await TableExistsAsync(conn, table))
            {
                missing.Add(table);
            }
        }

        Assert.True(
            missing.Count == 0,
            $"{missing.Count} table(s) Schema.sql declares do not exist after upgrading a "
            + $"{baseline.Tag} database — a statement earlier in the file failed and SQLite "
            + $"truncated the rest of the batch without surfacing it: {string.Join(", ", missing)}");

        var columns = await ColumnsAsync(conn, "tenant_artifact_access");
        Assert.Contains("content_hash", columns);
        Assert.Contains("blob_key", columns);
        Assert.Contains("size_bytes", columns);

        Assert.True(
            await IndexExistsAsync(conn, "idx_tenant_artifact_access_blob_key"),
            "the tenant blob_key index must exist after an upgrade boot — the shared-blob refcount "
            + "scans the whole table without it, once per eviction, in a loop");
    }

    [Fact]
    public async Task Upgrading_SeedsEveryExistingTenantsContentBindingFromTheRowItIsServed()
    {
        var baseline = ResolveBaselineOrSkip();
        if (baseline is null)
        {
            return;
        }

        await ApplyBaselineSchemaAsync(baseline.SqliteSql);

        const string sharedHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        await using (var seed = await _db.OpenAsync())
        {
            await seed.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o-a','a'), ('o-b','b')");
            await seed.ExecuteAsync(
                """
                INSERT INTO cache_artifact
                    (id, ecosystem, name, version, filename, blob_key, content_hash, size_bytes,
                     first_cached_at, last_accessed_at)
                VALUES ('ca-1','npm','left-pad','1.0.0','left-pad-1.0.0.tgz',
                        @blobKey, @hash, 4096, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')
                """,
                new { blobKey = $"proxy/{sharedHash}/left-pad-1.0.0.tgz", hash = sharedHash });
            await seed.ExecuteAsync(
                """
                INSERT INTO tenant_artifact_access
                    (org_id, cache_artifact_id, first_accessed_at, last_accessed_at, access_count)
                VALUES ('o-a','ca-1','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z',1),
                       ('o-b','ca-1','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z',1)
                """);
        }

        await new SchemaInitializer(_db).InitializeAsync();

        await using var conn = await _db.OpenAsync();
        var bound = (await conn.QueryAsync<(string OrgId, string? ContentHash, string? BlobKey, long? SizeBytes)>(
            """
            SELECT org_id AS OrgId, content_hash AS ContentHash, blob_key AS BlobKey,
                   size_bytes AS SizeBytes
            FROM tenant_artifact_access
            WHERE cache_artifact_id = 'ca-1'
            ORDER BY org_id
            """)).ToList();

        Assert.Equal(2, bound.Count);
        foreach ((_, string? contentHash, string? blobKey, long? sizeBytes) in bound)
        {
            // Bound to exactly what that tenant is being served today, so the binding-first serve
            // projections are a no-op for data that predates them.
            Assert.Equal(sharedHash, contentHash);
            Assert.Equal($"proxy/{sharedHash}/left-pad-1.0.0.tgz", blobKey);
            Assert.Equal(4096, sizeBytes);
        }
    }

    private static SchemaBaseline? ResolveBaselineOrSkip()
    {
        var resolution = SchemaBaselineResolver.Resolve();
        if (resolution.Baseline is not null)
        {
            return resolution.Baseline;
        }

        Assert.True(
            SchemaBaselineResolver.IsTolerable(
                resolution,
                string.Equals(
                    Environment.GetEnvironmentVariable("SCHEMA_BACKCOMPAT_REQUIRE_BASELINE"),
                    "true",
                    StringComparison.OrdinalIgnoreCase)),
            $"the previous release's schema could not be resolved ({resolution.Absence}), so the "
            + "upgrade path was never exercised: " + resolution.Log);
        return null;
    }

    private async Task ApplyBaselineSchemaAsync(string sql)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(sql);
    }

    private static async Task<bool> TableExistsAsync(System.Data.Common.DbConnection conn, string table) =>
        await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = @table",
            new { table }) > 0;

    private static async Task<bool> IndexExistsAsync(System.Data.Common.DbConnection conn, string index) =>
        await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = @index",
            new { index }) > 0;

    private static async Task<List<string>> ColumnsAsync(System.Data.Common.DbConnection conn, string table)
    {
        // rawsql: PRAGMA table_info takes no bound parameter; the table name is a test constant.
        var rows = await conn.QueryAsync($"PRAGMA table_info({table})");
        return rows.Select(r => (string)r.name).ToList();
    }
}
