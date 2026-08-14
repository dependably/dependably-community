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
            INSERT INTO cargo_metadata (version_id, index_line, owner_kind)
            VALUES (@versionId, @indexLine, 'package_version')
            ON CONFLICT (version_id) WHERE owner_kind = 'package_version' DO UPDATE SET index_line = excluded.index_line
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
                INSERT INTO cargo_metadata (version_id, index_line, owner_kind)
                VALUES (@versionId, @indexLine, 'package_version')
                ON CONFLICT (version_id) WHERE owner_kind = 'package_version' DO UPDATE SET index_line = excluded.index_line
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

    // Seeds a global-plane (cache_artifact) crate: the shared row plus this tenant's own
    // content binding on tenant_artifact_access, and the sparse-index line stored against the
    // cache_artifact_id (owner_kind='cache_artifact') the way ProxyCrateFromUpstreamAsync writes
    // it on first fetch — with cksum equal to sharedHash, exactly as BuildProxyIndexLine
    // computes it from whichever tenant's fetch created the row.
    private async Task<string> SeedGlobalIndexLineAsync(
        string orgId, string name, string version, string sharedHash, string ownHash)
    {
        var cacheArtifacts = new CacheArtifactRepository(_fixture.Store);
        var cacheArtifact = new CacheArtifact
        {
            Id = Guid.NewGuid().ToString("D"),
            Ecosystem = "cargo",
            Name = name,
            Version = version,
            Filename = $"{name}-{version}.crate",
            BlobKey = $"proxy/{sharedHash}/{name}-{version}.crate",
            ContentHash = sharedHash,
            SizeBytes = 10,
            FirstCachedAt = TestTime.KnownNow,
            LastAccessedAt = TestTime.KnownNow,
        };
        await cacheArtifacts.InsertAsync(cacheArtifact);

        await new TenantArtifactAccessRepository(_fixture.Store).UpsertAsync(
            orgId, cacheArtifact.Id, TestTime.KnownNow,
            new TenantContentBinding(ownHash, $"proxy/{ownHash}/{name}-{version}.crate", 10));

        string indexLine =
            $$"""{"name":"{{name}}","vers":"{{version}}","deps":[],"cksum":"{{sharedHash}}","features":{},"yanked":false}""";
        await NewRepo().UpsertIndexLineForCacheArtifactAsync(cacheArtifact.Id, indexLine);

        return cacheArtifact.Id;
    }

    /// <summary>
    /// A tenant whose own upstream served different bytes than the shared row's must not be
    /// advertised the shared row's <c>cksum</c> — it describes another tenant's <c>.crate</c>
    /// file. Unlike npm's <c>dist.integrity</c>, Cargo's sparse-index format has no "absent"
    /// form for <c>cksum</c>, so the line is rewritten to this tenant's own bound content hash
    /// (the same SHA-256-of-the-.crate-file digest) rather than omitted.
    /// </summary>
    [Fact]
    public async Task GetIndexLinesAsync_ForADivergingTenant_RewritesCksumToTheTenantsOwnHash()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        string name = $"left-pad-{Guid.NewGuid():N}"[..20];
        const string sharedHash = "1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa";
        const string ownHash = "2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb";

        await SeedGlobalIndexLineAsync(orgId, name, "1.3.0", sharedHash, ownHash);

        var repo = NewRepo();
        var lines = await repo.GetIndexLinesAsync(orgId, name);

        string line = Assert.Single(lines);
        using var doc = System.Text.Json.JsonDocument.Parse(line);
        Assert.Equal(ownHash, doc.RootElement.GetProperty("cksum").GetString());
        Assert.DoesNotContain(sharedHash, line);
    }

    /// <summary>
    /// Adversarial twin: the non-diverging tenant — every tenant, on every coordinate, in
    /// normal operation — keeps the shared row's own <c>cksum</c> verbatim. Rewriting it
    /// unconditionally would also pass the test above while corrupting every crate this tenant
    /// resolved from the same bytes as the shared row.
    /// </summary>
    [Fact]
    public async Task GetIndexLinesAsync_ForANonDivergingTenant_KeepsTheSharedCksum()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        string name = $"right-pad-{Guid.NewGuid():N}"[..20];
        const string hash = "1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa";

        await SeedGlobalIndexLineAsync(orgId, name, "1.3.0", hash, hash);

        var repo = NewRepo();
        var lines = await repo.GetIndexLinesAsync(orgId, name);

        string line = Assert.Single(lines);
        using var doc = System.Text.Json.JsonDocument.Parse(line);
        Assert.Equal(hash, doc.RootElement.GetProperty("cksum").GetString());
    }

    /// <summary>
    /// A tenant with no binding at all is being served the shared blob, so the shared row's
    /// <c>cksum</c> describes exactly those bytes and must be kept verbatim. This is the
    /// legacy/blue-green row shape, and it is the case where treating "hashes are not equal" as
    /// the test rather than "both hashes are known and unequal" would rewrite (or blank) the
    /// cksum of every un-backfilled proxy crate.
    /// </summary>
    [Fact]
    public async Task GetIndexLinesAsync_WithNoTenantBinding_KeepsTheSharedCksum()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        string name = $"no-pad-{Guid.NewGuid():N}"[..20];
        const string hash = "1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa";

        var cacheArtifacts = new CacheArtifactRepository(_fixture.Store);
        var cacheArtifact = new CacheArtifact
        {
            Id = Guid.NewGuid().ToString("D"),
            Ecosystem = "cargo",
            Name = name,
            Version = "1.3.0",
            Filename = $"{name}-1.3.0.crate",
            BlobKey = $"proxy/{hash}/{name}-1.3.0.crate",
            ContentHash = hash,
            SizeBytes = 10,
            FirstCachedAt = TestTime.KnownNow,
            LastAccessedAt = TestTime.KnownNow,
        };
        await cacheArtifacts.InsertAsync(cacheArtifact);

        await new TenantArtifactAccessRepository(_fixture.Store).UpsertAsync(
            orgId, cacheArtifact.Id, TestTime.KnownNow, TenantContentBinding.None);

        string indexLine =
            $$"""{"name":"{{name}}","vers":"1.3.0","deps":[],"cksum":"{{hash}}","features":{},"yanked":false}""";
        await NewRepo().UpsertIndexLineForCacheArtifactAsync(cacheArtifact.Id, indexLine);

        var repo = NewRepo();
        var lines = await repo.GetIndexLinesAsync(orgId, name);

        string line = Assert.Single(lines);
        using var doc = System.Text.Json.JsonDocument.Parse(line);
        Assert.Equal(hash, doc.RootElement.GetProperty("cksum").GetString());
    }
}
