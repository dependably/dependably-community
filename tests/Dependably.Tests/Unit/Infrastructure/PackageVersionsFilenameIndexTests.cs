using Dapper;
using Dependably.Infrastructure;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Xunit;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Acceptance: the PyPI/npm/NuGet download lookup must equality-probe the
/// idx_package_versions_filename index instead of running a leading-wildcard LIKE
/// over the whole table. Also covers the SchemaInitializer backfill that populates
/// `filename` for rows that pre-date the column.
/// </summary>
[Trait("Category", "Unit")]
public sealed class PackageVersionsFilenameIndexTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync() =>
        await new SchemaInitializer(_db).InitializeAsync();

    public async Task DisposeAsync() => await _db.DisposeAsync();

    [Fact]
    public async Task FindByFilenameQuery_UsesIndex()
    {
        await using var conn = await _db.OpenAsync();
        var plan = (await conn.QueryAsync<(int Id, int Parent, int NotUsed, string Detail)>(
            """
            EXPLAIN QUERY PLAN
            SELECT pv.id FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE pv.filename = @filename AND p.org_id = @orgId AND p.ecosystem = @ecosystem
            LIMIT 1
            """,
            new { filename = "acme-1.0.tar.gz", orgId = "o1", ecosystem = "pypi" })).ToList();

        Assert.NotEmpty(plan);
        var detail = string.Join("\n", plan.Select(p => p.Detail));
        Assert.Contains("idx_package_versions_filename", detail);
        // The previous LIKE-on-blob_key plan reported "SCAN package_versions"; the index
        // path reports SEARCH using the new index. Either substring keeps the assertion
        // resilient to SQLite's exact wording.
        Assert.Contains("SEARCH", detail);
    }

    [Fact]
    public async Task CreateVersion_PopulatesFilenameFromBlobKey()
    {
        var repo = new PackageRepository(_db);
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO orgs (id, slug) VALUES ('o1', 'acme')");
        }
        var pkg = await repo.GetOrCreateAsync("o1", "pypi", "demo", "demo", isProxy: false);

        var blobKey = BlobKeys.Hosted("o1", "pypi", "demo", "1.0", "demo-1.0.tar.gz");
        var v = await repo.CreateVersionAsync(new NewPackageVersion(
            pkg.Id, "1.0", "pkg:pypi/demo@1.0", blobKey, 100, "deadbeef"));

        await using var conn2 = await _db.OpenAsync();
        var filename = await conn2.ExecuteScalarAsync<string?>(
            "SELECT filename FROM package_versions WHERE id = @id", new { id = v.Id });
        Assert.Equal("demo-1.0.tar.gz", filename);
    }

    [Fact]
    public async Task FindVersionByBlobKeySuffixAsync_FindsByFilename()
    {
        var repo = new PackageRepository(_db);
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme')");
        }
        var pkg = await repo.GetOrCreateAsync("o1", "pypi", "demo", "demo", isProxy: false);
        var blobKey = BlobKeys.Hosted("o1", "pypi", "demo", "2.0", "demo-2.0.tar.gz");
        _ = await repo.CreateVersionAsync(new NewPackageVersion(
            pkg.Id, "2.0", "pkg:pypi/demo@2.0", blobKey, 100, "cafebabe"));

        var found = await repo.FindVersionByBlobKeySuffixAsync("o1", "pypi", "demo-2.0.tar.gz");
        Assert.NotNull(found);
        Assert.Equal("2.0", found.Value.Version.Version);
        Assert.Equal("demo-2.0.tar.gz", found.Value.Version.BlobKey.Split('/')[^1]);
    }

    [Fact]
    public async Task BackfillPopulatesFilenameForLegacyRows()
    {
        // Simulate a row inserted before the filename column existed: clear it.
        var repo = new PackageRepository(_db);
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme')");
        }
        var pkg = await repo.GetOrCreateAsync("o1", "pypi", "legacy", "legacy", isProxy: true);
        _ = await repo.CreateVersionAsync(new NewPackageVersion(
            pkg.Id, "0.1", "pkg:pypi/legacy@0.1", "proxy/abc123/legacy-0.1.tar.gz", 50, "dead"));

        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync("UPDATE package_versions SET filename = NULL");
        }
        // Re-run the initializer's full pipeline to trigger the RunOnce backfill. The ledger
        // entry from the InitializeAsync call in IAsyncLifetime is dropped first so the
        // RunOnce gate doesn't skip the action.
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "DELETE FROM _applied_migrations WHERE name = 'backfill_package_versions_filename'");
        }
        await new SchemaInitializer(_db).InitializeAsync();

        await using var conn2 = await _db.OpenAsync();
        var filename = await conn2.ExecuteScalarAsync<string?>(
            "SELECT filename FROM package_versions LIMIT 1");
        Assert.Equal("legacy-0.1.tar.gz", filename);
    }
}
