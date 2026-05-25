using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Xunit;

namespace Dependably.Tests.Unit.Infrastructure;

[Trait("Category", "Unit")]
public sealed class PackageRepositoryTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;
    private readonly PackageRepository _repo;

    public PackageRepositoryTests(InMemoryDbFixture fixture)
    {
        _fixture = fixture;
        _repo = new PackageRepository(_fixture.Store);
    }

    // Per-test unique purl scope. package_versions.purl is UNIQUE globally, so any test
    // that inserts a version must namespace its purls — the IClassFixture instance is
    // shared and the schema constraint isn't.
    private static string Purl(string version = "1.0.0", string name = "acme")
        => $"pkg:npm/{Guid.NewGuid():N}/{name}@{version}";

    // ── ListAsync ────────────────────────────────────────────────────────────

    [Fact]
    public async Task ListAsync_FiltersByOrgAndEcosystem_AndOrdersByPurlName()
    {
        var orgA = await OrgSeeder.InsertAsync(_fixture.Store, $"orga-{Guid.NewGuid():N}");
        var orgB = await OrgSeeder.InsertAsync(_fixture.Store, $"orgb-{Guid.NewGuid():N}");
        await PackageSeeder.InsertAsync(_fixture.Store, orgA, "npm", "zebra");
        await PackageSeeder.InsertAsync(_fixture.Store, orgA, "npm", "apple");
        await PackageSeeder.InsertAsync(_fixture.Store, orgA, "pypi", "should-not-appear");
        await PackageSeeder.InsertAsync(_fixture.Store, orgB, "npm", "in-other-org");

        var list = await _repo.ListAsync(orgA, "npm");

        Assert.Equal(2, list.Count);
        Assert.Equal("apple", list[0].PurlName);
        Assert.Equal("zebra", list[1].PurlName);
    }

    [Fact]
    public async Task ListAsync_WrongOrg_ReturnsEmpty()
    {
        var orgA = await OrgSeeder.InsertAsync(_fixture.Store, $"orga-{Guid.NewGuid():N}");
        await PackageSeeder.InsertAsync(_fixture.Store, orgA, "npm", "pkg");

        var list = await _repo.ListAsync($"ghost-{Guid.NewGuid():N}", "npm");
        Assert.Empty(list);
    }

    // ── GetByPurlNameAsync / GetOrCreateAsync ────────────────────────────────

    [Fact]
    public async Task GetByPurlNameAsync_Missing_ReturnsNull()
    {
        var orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        Assert.Null(await _repo.GetByPurlNameAsync(orgId, "npm", "nope"));
    }

    [Fact]
    public async Task GetOrCreateAsync_FirstCall_Inserts_SecondCall_Idempotent()
    {
        // Pinning idempotency — concurrency assumption in the plan.
        var orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        var first  = await _repo.GetOrCreateAsync(orgId, "npm", "acme", "acme", isProxy: false);
        var second = await _repo.GetOrCreateAsync(orgId, "npm", "acme", "acme", isProxy: false);

        Assert.Equal(first.Id, second.Id);

        await using var conn = await _fixture.Store.OpenAsync();
        var count = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM packages WHERE org_id = @orgId AND purl_name = 'acme'",
            new { orgId });
        Assert.Equal(1, count);
    }

    [Fact]
    public async Task GetOrCreateAsync_DifferentOrgs_AreDistinctEvenWithSameName()
    {
        var orgA = await OrgSeeder.InsertAsync(_fixture.Store, $"orga-{Guid.NewGuid():N}");
        var orgB = await OrgSeeder.InsertAsync(_fixture.Store, $"orgb-{Guid.NewGuid():N}");
        var a = await _repo.GetOrCreateAsync(orgA, "npm", "shared", "shared", isProxy: false);
        var b = await _repo.GetOrCreateAsync(orgB, "npm", "shared", "shared", isProxy: false);

        Assert.NotEqual(a.Id, b.Id);
    }

    // ── Version CRUD ─────────────────────────────────────────────────────────

    [Fact]
    public async Task CreateVersionAsync_RoundTrip_PopulatesFields()
    {
        var orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        var pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "acme");

        var v = await _repo.CreateVersionAsync(new NewPackageVersion(
            pkgId, "1.0.0", Purl(), "blob/key", 100, "sha256hex", FirstFetch: true, Origin: "uploaded"));

        Assert.Equal("1.0.0", v.Version);
        Assert.Equal("uploaded", v.Origin);
        Assert.True(v.FirstFetch);
        Assert.Null(v.PublishedAt);
    }

    [Fact]
    public async Task CreateVersionAsync_UpstreamIntegrity_RoundTripsThroughGetVersions()
    {
        var orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        var pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "acme");

        var created = await _repo.CreateVersionAsync(new NewPackageVersion(
            pkgId, "1.0.0", Purl(), "blob/key", 100, "sha256hex",
            FirstFetch: true,
            UpstreamIntegrityValue: "sha512-aGVsbG8=",
            UpstreamIntegrityAlgorithm: "sha512-sri"));

        Assert.Equal("sha512-aGVsbG8=", created.UpstreamIntegrityValue);
        Assert.Equal("sha512-sri", created.UpstreamIntegrityAlgorithm);
        var fetched = await _repo.GetVersionByIdAsync(orgId, created.Id);
        Assert.Equal("sha512-aGVsbG8=", fetched!.UpstreamIntegrityValue);
        Assert.Equal("sha512-sri", fetched!.UpstreamIntegrityAlgorithm);
        var list = await _repo.GetVersionsAsync(pkgId);
        Assert.Equal("sha512-aGVsbG8=", list[0].UpstreamIntegrityValue);
    }

    [Fact]
    public async Task CreateVersionAsync_ChecksumSha1_RoundTripsThroughGetVersions()
    {
        var orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        var pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "acme");

        var created = await _repo.CreateVersionAsync(new NewPackageVersion(
            pkgId, "1.0.0", Purl(), "blob/key", 100, "sha256hex",
            FirstFetch: true, ChecksumSha1: "abc123def456"));

        Assert.Equal("abc123def456", created.ChecksumSha1);
        var fetched = await _repo.GetVersionByIdAsync(orgId, created.Id);
        Assert.Equal("abc123def456", fetched!.ChecksumSha1);
        var list = await _repo.GetVersionsAsync(pkgId);
        Assert.Equal("abc123def456", list[0].ChecksumSha1);
    }

    [Fact]
    public async Task CreateVersionAsync_PublishedAt_RoundTripsThroughGetVersions()
    {
        var orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        var pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "acme");
        var publishedAt = new DateTimeOffset(2023, 9, 30, 14, 23, 31, TimeSpan.Zero);

        var created = await _repo.CreateVersionAsync(new NewPackageVersion(
            pkgId, "1.0.0", Purl(), "blob/key", 100, "sha256hex",
            FirstFetch: true, PublishedAt: publishedAt));

        Assert.Equal(publishedAt, created.PublishedAt);

        var fetched = await _repo.GetVersionByIdAsync(orgId, created.Id);
        Assert.NotNull(fetched);
        Assert.Equal(publishedAt, fetched!.PublishedAt);

        var list = await _repo.GetVersionsAsync(pkgId);
        Assert.Equal(publishedAt, list[0].PublishedAt);
    }

    [Fact]
    public async Task GetVersionsAsync_OrdersNewestFirst()
    {
        var orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        var pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "acme");
        await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgId, "1.0.0", Purl("1.0.0"), blobKey: $"k1-{Guid.NewGuid():N}");
        await Task.Delay(1100);   // SQLite default created_at has 1-second resolution
        await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgId, "2.0.0", Purl("2.0.0"), blobKey: $"k2-{Guid.NewGuid():N}");

        var versions = await _repo.GetVersionsAsync(pkgId);
        Assert.Equal("2.0.0", versions[0].Version);
    }

    [Fact]
    public async Task GetVersionByBlobKeyAsync_FindsByExactKey()
    {
        var orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        var pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "acme");
        var blobKey = $"unique/path/{Guid.NewGuid():N}";
        await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgId, "1.0.0", Purl(), blobKey: blobKey);

        var v = await _repo.GetVersionByBlobKeyAsync(orgId, blobKey);

        Assert.NotNull(v);
        Assert.Equal("1.0.0", v!.Version);
    }

    [Fact]
    public async Task GetVersionByBlobKeyAsync_OrgMismatch_ReturnsNull()
    {
        // Defence-in-depth: even though blob_key is globally unique today, the lookup must
        // refuse to return a row whose parent package belongs to a different tenant.
        var orgA = await OrgSeeder.InsertAsync(_fixture.Store, $"orgA-{Guid.NewGuid():N}");
        var orgB = await OrgSeeder.InsertAsync(_fixture.Store, $"orgB-{Guid.NewGuid():N}");
        var pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgA, "npm", "acme");
        var blobKey = $"unique/path/{Guid.NewGuid():N}";
        await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgId, "1.0.0", Purl(), blobKey: blobKey);

        Assert.NotNull(await _repo.GetVersionByBlobKeyAsync(orgA, blobKey));
        Assert.Null(await _repo.GetVersionByBlobKeyAsync(orgB, blobKey));
    }

    [Fact]
    public async Task GetVersionByIdAsync_OrgMismatch_ReturnsNull()
    {
        var orgA = await OrgSeeder.InsertAsync(_fixture.Store, $"orgA-{Guid.NewGuid():N}");
        var orgB = await OrgSeeder.InsertAsync(_fixture.Store, $"orgB-{Guid.NewGuid():N}");
        var pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgA, "npm", "acme");
        var verId = await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgId, "1.0.0", Purl());

        Assert.NotNull(await _repo.GetVersionByIdAsync(orgA, verId));
        Assert.Null(await _repo.GetVersionByIdAsync(orgB, verId));
    }

    [Fact]
    public async Task UpdateDeprecatedAsync_SetsAndClears()
    {
        var orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        var pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "acme");
        var verId = await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgId, "1.0.0", Purl());

        await _repo.UpdateDeprecatedAsync(verId, "moved to @scope/acme");
        Assert.Equal("moved to @scope/acme", (await _repo.GetVersionByIdAsync(orgId, verId))!.Deprecated);

        await _repo.UpdateDeprecatedAsync(verId, null);
        Assert.Null((await _repo.GetVersionByIdAsync(orgId, verId))!.Deprecated);
    }

    [Fact]
    public async Task UpdateVersionForOverwriteAsync_RewritesArtifactFields_AndClearsVulnChecked()
    {
        var orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        var pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "acme");
        var verId = await PackageSeeder.InsertVersionAsync(
            _fixture.Store, pkgId, "1.0.0", Purl(), blobKey: $"old-{Guid.NewGuid():N}", sizeBytes: 100, checksumSha256: "old-sha");

        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE package_versions SET vuln_checked_at = '2026-01-01T00:00:00Z' WHERE id = @id",
                new { id = verId });
        }

        await _repo.UpdateVersionForOverwriteAsync(verId, "new-blob", 200, "new-sha", "uploaded", sha1: "new-sha1");

        var v = (await _repo.GetVersionByIdAsync(orgId, verId))!;
        Assert.Equal("new-blob", v.BlobKey);
        Assert.Equal(200, v.SizeBytes);
        Assert.Equal("new-sha", v.ChecksumSha256);
        Assert.Equal("new-sha1", v.ChecksumSha1);
        Assert.Equal("uploaded", v.Origin);
        Assert.Null(v.VulnCheckedAt);
    }

    // ── Pagination ───────────────────────────────────────────────────────────

    [Fact]
    public async Task ListPaginatedAsync_Search_EscapesWildcards_AndOnlyMatchesLiteral()
    {
        // "ev_il" should be treated as the literal substring, not the SQL wildcard pattern.
        var orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "ev_il");
        await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "evxil");

        var (items, total) = await _repo.ListPaginatedAsync(new PackageListQuery(
            OrgId: orgId, Limit: 50, Offset: 0, Ecosystem: "npm", Search: "ev_il"));

        Assert.Equal(1, total);
        Assert.Single(items);
        Assert.Equal("ev_il", items[0].Name);
    }

    [Fact]
    public async Task ListPaginatedAsync_OffsetAndLimit_RespectBoundaries()
    {
        var orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        for (var i = 0; i < 5; i++) await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", $"pkg-{i:D2}");

        var page1 = await _repo.ListPaginatedAsync(new PackageListQuery(orgId, Limit: 2, Offset: 0, Ecosystem: "npm", SortBy: "name", SortDir: "asc"));
        Assert.Equal(5, page1.Total);
        Assert.Equal(2, page1.Items.Count);

        var lastPage = await _repo.ListPaginatedAsync(new PackageListQuery(orgId, Limit: 2, Offset: 4, Ecosystem: "npm", SortBy: "name", SortDir: "asc"));
        Assert.Single(lastPage.Items);

        var beyondEnd = await _repo.ListPaginatedAsync(new PackageListQuery(orgId, Limit: 2, Offset: 99, Ecosystem: "npm"));
        Assert.Empty(beyondEnd.Items);
    }

    [Theory]
    [InlineData("name", "asc")]
    [InlineData("name", "desc")]
    [InlineData("purl", "asc")]
    [InlineData("ecosystem", "asc")]
    [InlineData("versions", "desc")]
    [InlineData("vulns", "desc")]
    [InlineData("unknown-sort-col", "asc")]    // falls through to created_at default
    public async Task ListPaginatedAsync_AllSortCombinationsExecute(string sortBy, string sortDir)
    {
        var orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "a");
        await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "b");

        var result = await _repo.ListPaginatedAsync(new PackageListQuery(
            orgId, Limit: 10, Offset: 0, Ecosystem: "npm", SortBy: sortBy, SortDir: sortDir));
        Assert.Equal(2, result.Total);
    }

    // ── Delete + proxy-purge ─────────────────────────────────────────────────

    [Fact]
    public async Task DeletePackageIfEmptyAsync_OnlyDeletes_WhenNoVersions()
    {
        var orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        var pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "acme");
        await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgId, "1.0.0", Purl());

        Assert.False(await _repo.DeletePackageIfEmptyAsync(pkgId));   // version present → no-op
        Assert.NotNull(await _repo.GetByPurlNameAsync(orgId, "npm", "acme"));

        await using (var conn = await _fixture.Store.OpenAsync())
            await conn.ExecuteAsync("DELETE FROM package_versions WHERE package_id = @id", new { id = pkgId });
        Assert.True(await _repo.DeletePackageIfEmptyAsync(pkgId));
        Assert.Null(await _repo.GetByPurlNameAsync(orgId, "npm", "acme"));
    }

    [Fact]
    public async Task DeleteProxyVersionsForNameAsync_TouchesOnlyProxyRows_ReturnsBlobKeys()
    {
        var orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        var pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "acme", isProxy: true);
        await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgId, "1.0.0", Purl("1.0.0"), origin: "proxy", blobKey: $"p1-{Guid.NewGuid():N}");
        await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgId, "2.0.0", Purl("2.0.0"), origin: "proxy", blobKey: $"p2-{Guid.NewGuid():N}");
        await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgId, "3.0.0", Purl("3.0.0"), origin: "uploaded", blobKey: $"u1-{Guid.NewGuid():N}");

        var blobKeys = await _repo.DeleteProxyVersionsForNameAsync(orgId, "npm", "acme");

        Assert.Equal(2, blobKeys.Count);
        Assert.All(blobKeys, k => Assert.StartsWith("p", k));

        var remaining = await _repo.GetVersionsAsync(pkgId);
        Assert.Single(remaining);
        Assert.Equal("uploaded", remaining[0].Origin);
    }
}
