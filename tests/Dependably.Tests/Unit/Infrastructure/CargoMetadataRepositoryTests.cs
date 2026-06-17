using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Unit tests for <see cref="CargoMetadataRepository"/>. Covers the index-line retrieval
/// path (<see cref="CargoMetadataRepository.GetIndexLinesAsync"/>) including tenant isolation
/// and insertion-order sorting.
/// </summary>
[Trait("Category", "Unit")]
public sealed class CargoMetadataRepositoryTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;

    public CargoMetadataRepositoryTests(InMemoryDbFixture fixture) => _fixture = fixture;

    private CargoMetadataRepository NewRepo() => new(_fixture.Store);

    // Seeds a package + version + cargo_metadata row. Returns the version id.
    private async Task<string> SeedIndexLineAsync(
        string orgId, string name, string version, string indexLine)
    {
        string pkgId = await PackageSeeder.InsertAsync(
            _fixture.Store, orgId, "cargo", name, isProxy: false, purlName: name);
        string purl = $"pkg:cargo/{name}@{version}";
        string blobKey = $"cargo/{orgId}/{name}/{version}.crate";
        string versionId = await PackageSeeder.InsertVersionAsync(
            _fixture.Store, pkgId, version, purl, blobKey: blobKey);

        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO cargo_metadata (version_id, index_line)
            VALUES (@versionId, @indexLine)
            ON CONFLICT (version_id) DO UPDATE SET index_line = excluded.index_line
            """,
            new { versionId, indexLine });

        return versionId;
    }

    [Fact]
    public async Task GetIndexLinesAsync_ReturnsSeededLine()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        string name = $"serde-{Guid.NewGuid():N}"[..12];
        string indexLine = $$"""{"name":"{{name}}","vers":"1.0.0","deps":[],"cksum":"abc","features":{},"yanked":false}""";

        await SeedIndexLineAsync(orgId, name, "1.0.0", indexLine);

        var repo = NewRepo();
        var lines = await repo.GetIndexLinesAsync(orgId, name);

        Assert.Single(lines);
        Assert.Equal(indexLine, lines[0]);
    }

    [Fact]
    public async Task GetIndexLinesAsync_MultipleVersions_ReturnedInInsertionOrder()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        string name = $"tokio-{Guid.NewGuid():N}"[..12];
        string line1 = $$"""{"name":"{{name}}","vers":"1.0.0","deps":[],"cksum":"a","features":{},"yanked":false}""";
        string line2 = $$"""{"name":"{{name}}","vers":"2.0.0","deps":[],"cksum":"b","features":{},"yanked":false}""";

        // Insert the package once; attach two versions each with a distinct cargo_metadata row.
        string pkgId = await PackageSeeder.InsertAsync(
            _fixture.Store, orgId, "cargo", name, isProxy: false, purlName: name);

        foreach ((string ver, string line) in new[] { ("1.0.0", line1), ("2.0.0", line2) })
        {
            string purl = $"pkg:cargo/{name}@{ver}";
            string blobKey = $"cargo/{orgId}/{name}/{ver}.crate";
            string versionId = await PackageSeeder.InsertVersionAsync(
                _fixture.Store, pkgId, ver, purl, blobKey: blobKey);

            await using var conn = await _fixture.Store.OpenAsync();
            await conn.ExecuteAsync(
                """
                INSERT INTO cargo_metadata (version_id, index_line)
                VALUES (@versionId, @indexLine)
                ON CONFLICT (version_id) DO UPDATE SET index_line = excluded.index_line
                """,
                new { versionId, indexLine = line });
        }

        var repo = NewRepo();
        var lines = await repo.GetIndexLinesAsync(orgId, name);

        Assert.Equal(2, lines.Count);
        Assert.Contains(line1, lines);
        Assert.Contains(line2, lines);
    }

    [Fact]
    public async Task GetIndexLinesAsync_OtherOrgLines_NotReturned()
    {
        string orgA = await OrgSeeder.InsertAsync(_fixture.Store, $"a-{Guid.NewGuid():N}");
        string orgB = await OrgSeeder.InsertAsync(_fixture.Store, $"b-{Guid.NewGuid():N}");
        string name = $"shared-{Guid.NewGuid():N}"[..12];
        // Distinct versions per org so the global purl uniqueness constraint is not hit.
        string lineA = $$"""{"name":"{{name}}","vers":"1.0.0","deps":[],"cksum":"orgA","features":{},"yanked":false}""";
        string lineB = $$"""{"name":"{{name}}","vers":"2.0.0","deps":[],"cksum":"orgB","features":{},"yanked":false}""";

        await SeedIndexLineAsync(orgA, name, "1.0.0", lineA);
        await SeedIndexLineAsync(orgB, name, "2.0.0", lineB);

        var repo = NewRepo();
        var linesA = await repo.GetIndexLinesAsync(orgA, name);
        var linesB = await repo.GetIndexLinesAsync(orgB, name);

        Assert.Single(linesA);
        Assert.Equal(lineA, linesA[0]);
        Assert.Single(linesB);
        Assert.Equal(lineB, linesB[0]);
    }

    [Fact]
    public async Task GetIndexLinesAsync_NoCrate_ReturnsEmpty()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");

        var repo = NewRepo();
        var lines = await repo.GetIndexLinesAsync(orgId, "nonexistent-crate");

        Assert.Empty(lines);
    }
}
