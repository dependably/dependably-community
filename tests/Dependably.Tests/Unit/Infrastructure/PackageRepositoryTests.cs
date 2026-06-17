using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;

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
        string orgA = await OrgSeeder.InsertAsync(_fixture.Store, $"orga-{Guid.NewGuid():N}");
        string orgB = await OrgSeeder.InsertAsync(_fixture.Store, $"orgb-{Guid.NewGuid():N}");
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
        string orgA = await OrgSeeder.InsertAsync(_fixture.Store, $"orga-{Guid.NewGuid():N}");
        await PackageSeeder.InsertAsync(_fixture.Store, orgA, "npm", "pkg");

        var list = await _repo.ListAsync($"ghost-{Guid.NewGuid():N}", "npm");
        Assert.Empty(list);
    }

    // ── GetByPurlNameAsync / GetOrCreateAsync ────────────────────────────────

    [Fact]
    public async Task GetByPurlNameAsync_Missing_ReturnsNull()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        Assert.Null(await _repo.GetByPurlNameAsync(orgId, "npm", "nope"));
    }

    [Fact]
    public async Task GetOrCreateAsync_FirstCall_Inserts_SecondCall_Idempotent()
    {
        // Pinning idempotency — concurrency assumption in the plan.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        var first = await _repo.GetOrCreateAsync(orgId, "npm", "acme", "acme", isProxy: false);
        var second = await _repo.GetOrCreateAsync(orgId, "npm", "acme", "acme", isProxy: false);

        Assert.Equal(first.Id, second.Id);

        await using var conn = await _fixture.Store.OpenAsync();
        long count = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM packages WHERE org_id = @orgId AND purl_name = 'acme'",
            new { orgId });
        Assert.Equal(1, count);
    }

    [Fact]
    public async Task GetOrCreateAsync_DifferentOrgs_AreDistinctEvenWithSameName()
    {
        string orgA = await OrgSeeder.InsertAsync(_fixture.Store, $"orga-{Guid.NewGuid():N}");
        string orgB = await OrgSeeder.InsertAsync(_fixture.Store, $"orgb-{Guid.NewGuid():N}");
        var a = await _repo.GetOrCreateAsync(orgA, "npm", "shared", "shared", isProxy: false);
        var b = await _repo.GetOrCreateAsync(orgB, "npm", "shared", "shared", isProxy: false);

        Assert.NotEqual(a.Id, b.Id);
    }

    // ── Version CRUD ─────────────────────────────────────────────────────────

    [Fact]
    public async Task CreateVersionAsync_RoundTrip_PopulatesFields()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "acme");

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
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "acme");

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
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "acme");

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
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "acme");
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
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "acme");
        await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgId, "1.0.0", Purl("1.0.0"), blobKey: $"k1-{Guid.NewGuid():N}");
        await Task.Delay(1100);   // SQLite default created_at has 1-second resolution
        await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgId, "2.0.0", Purl("2.0.0"), blobKey: $"k2-{Guid.NewGuid():N}");

        var versions = await _repo.GetVersionsAsync(pkgId);
        Assert.Equal("2.0.0", versions[0].Version);
    }

    [Fact]
    public async Task GetVersionByBlobKeyAsync_FindsByExactKey()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "acme");
        string blobKey = $"unique/path/{Guid.NewGuid():N}";
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
        string orgA = await OrgSeeder.InsertAsync(_fixture.Store, $"orgA-{Guid.NewGuid():N}");
        string orgB = await OrgSeeder.InsertAsync(_fixture.Store, $"orgB-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgA, "npm", "acme");
        string blobKey = $"unique/path/{Guid.NewGuid():N}";
        await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgId, "1.0.0", Purl(), blobKey: blobKey);

        Assert.NotNull(await _repo.GetVersionByBlobKeyAsync(orgA, blobKey));
        Assert.Null(await _repo.GetVersionByBlobKeyAsync(orgB, blobKey));
    }

    [Fact]
    public async Task GetVersionByIdAsync_OrgMismatch_ReturnsNull()
    {
        string orgA = await OrgSeeder.InsertAsync(_fixture.Store, $"orgA-{Guid.NewGuid():N}");
        string orgB = await OrgSeeder.InsertAsync(_fixture.Store, $"orgB-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgA, "npm", "acme");
        string verId = await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgId, "1.0.0", Purl());

        Assert.NotNull(await _repo.GetVersionByIdAsync(orgA, verId));
        Assert.Null(await _repo.GetVersionByIdAsync(orgB, verId));
    }

    [Fact]
    public async Task UpdateDeprecatedAsync_SetsAndClears()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "acme");
        string verId = await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgId, "1.0.0", Purl());

        await _repo.UpdateDeprecatedAsync(verId, "moved to @scope/acme");
        Assert.Equal("moved to @scope/acme", (await _repo.GetVersionByIdAsync(orgId, verId))!.Deprecated);

        await _repo.UpdateDeprecatedAsync(verId, null);
        Assert.Null((await _repo.GetVersionByIdAsync(orgId, verId))!.Deprecated);
    }

    [Fact]
    public async Task UpdateVersionForOverwriteAsync_RewritesArtifactFields_AndClearsVulnChecked()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "acme");
        string verId = await PackageSeeder.InsertVersionAsync(
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
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
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
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        for (int i = 0; i < 5; i++)
        {
            await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", $"pkg-{i:D2}");
        }

        var (Items, Total) = await _repo.ListPaginatedAsync(new PackageListQuery(orgId, Limit: 2, Offset: 0, Ecosystem: "npm", SortBy: "name", SortDir: "asc"));
        Assert.Equal(5, Total);
        Assert.Equal(2, Items.Count);

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
    [InlineData("downloads", "desc")]
    [InlineData("downloads", "asc")]
    [InlineData("unknown-sort-col", "asc")]    // falls through to created_at default
    public async Task ListPaginatedAsync_AllSortCombinationsExecute(string sortBy, string sortDir)
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "a");
        await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "b");
        var (_, Total) = await _repo.ListPaginatedAsync(new PackageListQuery(
            orgId, Limit: 10, Offset: 0, Ecosystem: "npm", SortBy: sortBy, SortDir: sortDir));
        Assert.Equal(2, Total);
    }

    // ── TotalDownloads + LatestState aggregates ──────────────────────────────

    [Fact]
    public async Task ListPaginatedAsync_TotalDownloads_SumsAcrossAllVersions()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "acme");
        string v1 = await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgId, "1.0.0", Purl("1.0.0"), origin: "proxy");
        string v2 = await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgId, "2.0.0", Purl("2.0.0"), origin: "uploaded");
        await SetDownloadCountAsync(v1, 7);
        await SetDownloadCountAsync(v2, 5);

        var (items, _) = await _repo.ListPaginatedAsync(new PackageListQuery(orgId, Limit: 10, Offset: 0, Ecosystem: "npm"));

        Assert.Equal(12, Assert.Single(items).TotalDownloads);
    }

    [Fact]
    public async Task ListPaginatedAsync_LatestState_UnknownWhenNoUpstreamBaseline()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "acme", isProxy: true);
        await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgId, "1.0.0", Purl("1.0.0"), origin: "proxy");

        var (items, _) = await _repo.ListPaginatedAsync(new PackageListQuery(orgId, Limit: 10, Offset: 0, Ecosystem: "npm"));

        var pkg = Assert.Single(items);
        Assert.Equal("unknown", pkg.LatestState);
        Assert.Null(pkg.UpstreamLatestVersion);
    }

    [Fact]
    public async Task ListPaginatedAsync_LatestState_CurrentWhenUpstreamLatestIsProxyCached()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "acme", isProxy: true);
        await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgId, "1.0.0", Purl("1.0.0"), origin: "proxy");
        await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgId, "2.0.0", Purl("2.0.0"), origin: "proxy");
        await _repo.UpdateUpstreamLatestAsync(pkgId, "2.0.0");

        var (items, _) = await _repo.ListPaginatedAsync(new PackageListQuery(orgId, Limit: 10, Offset: 0, Ecosystem: "npm"));

        var pkg = Assert.Single(items);
        Assert.Equal("current", pkg.LatestState);
        Assert.Equal("2.0.0", pkg.UpstreamLatestVersion);
    }

    [Fact]
    public async Task ListPaginatedAsync_LatestState_StaleWhenUpstreamLatestNotCached()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "acme", isProxy: true);
        await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgId, "1.0.0", Purl("1.0.0"), origin: "proxy");
        // Upstream's latest (3.0.0) is newer than anything cached locally.
        await _repo.UpdateUpstreamLatestAsync(pkgId, "3.0.0");

        var (items, _) = await _repo.ListPaginatedAsync(new PackageListQuery(orgId, Limit: 10, Offset: 0, Ecosystem: "npm"));

        Assert.Equal("stale", Assert.Single(items).LatestState);
    }

    [Fact]
    public async Task ListPaginatedAsync_LatestState_StaleWhenUpstreamLatestExistsOnlyAsUploaded()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "acme", isProxy: true);
        // A locally uploaded row at the upstream-latest version does NOT count as proxy-cached.
        await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgId, "2.0.0", Purl("2.0.0"), origin: "uploaded");
        await _repo.UpdateUpstreamLatestAsync(pkgId, "2.0.0");

        var (items, _) = await _repo.ListPaginatedAsync(new PackageListQuery(orgId, Limit: 10, Offset: 0, Ecosystem: "npm"));

        Assert.Equal("stale", Assert.Single(items).LatestState);
    }

    private async Task SetDownloadCountAsync(string versionId, long count)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE package_versions SET download_count = @count WHERE id = @id",
            new { count, id = versionId });
    }

    // ── Malicious / advisory derived flags ───────────────────────────────────

    [Fact]
    public async Task GetVersionsAsync_MalAdvisory_SetsIsMaliciousAndHasAdvisory()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "evil");
        string verId = await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgId, "1.0.0", Purl());
        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
            _fixture.Store, osvId: "MAL-2024-" + Guid.NewGuid().ToString("N")[..8], severity: null, cvssScore: null);
        await VulnerabilitySeeder.LinkAsync(_fixture.Store, verId, vulnId);

        var ver = Assert.Single(await _repo.GetVersionsAsync(pkgId));
        Assert.True(ver.IsMalicious);
        Assert.True(ver.HasAdvisory);
    }

    [Fact]
    public async Task GetVersionsAsync_NonMalAdvisory_HasAdvisoryButNotMalicious()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "vuln");
        string verId = await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgId, "1.0.0", Purl());
        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
            _fixture.Store, osvId: "GHSA-" + Guid.NewGuid().ToString("N")[..8], cvssScore: 5.0);
        await VulnerabilitySeeder.LinkAsync(_fixture.Store, verId, vulnId);

        var ver = Assert.Single(await _repo.GetVersionsAsync(pkgId));
        Assert.False(ver.IsMalicious);
        Assert.True(ver.HasAdvisory);
    }

    [Fact]
    public async Task GetVersionsAsync_NoAdvisory_BothFlagsFalse()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "acme");
        await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgId, "1.0.0", Purl());

        var ver = Assert.Single(await _repo.GetVersionsAsync(pkgId));
        Assert.False(ver.IsMalicious);
        Assert.False(ver.HasAdvisory);
    }

    [Fact]
    public async Task ListPaginatedAsync_HasMaliciousVersion_TrueWhenAnyVersionLinkedToMal()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "evil");
        // First version clean; second version carries the MAL- advisory.
        await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgId, "1.0.0", Purl("1.0.0"));
        string malVerId = await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgId, "2.0.0", Purl("2.0.0"));
        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
            _fixture.Store, osvId: "MAL-2024-" + Guid.NewGuid().ToString("N")[..8], severity: null, cvssScore: null);
        await VulnerabilitySeeder.LinkAsync(_fixture.Store, malVerId, vulnId);

        var (items, _) = await _repo.ListPaginatedAsync(new PackageListQuery(orgId, Limit: 10, Offset: 0, Ecosystem: "npm"));
        Assert.True(Assert.Single(items).HasMaliciousVersion);
    }

    [Fact]
    public async Task ListPaginatedAsync_HasMaliciousVersion_FalseForCleanPackage()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "good");
        string verId = await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgId, "1.0.0", Purl());
        // A non-MAL advisory does not flip the malicious flag.
        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
            _fixture.Store, osvId: "GHSA-" + Guid.NewGuid().ToString("N")[..8], cvssScore: 5.0);
        await VulnerabilitySeeder.LinkAsync(_fixture.Store, verId, vulnId);

        var (items, _) = await _repo.ListPaginatedAsync(new PackageListQuery(orgId, Limit: 10, Offset: 0, Ecosystem: "npm"));
        Assert.False(Assert.Single(items).HasMaliciousVersion);
    }

    [Fact]
    public async Task MaliciousFlags_DoNotLeakAcrossOrgs()
    {
        // Org B's package shares a name with org A's malicious package but has no MAL link;
        // the flag must stay scoped to the org that actually owns the malicious version.
        string orgA = await OrgSeeder.InsertAsync(_fixture.Store, $"orgA-{Guid.NewGuid():N}");
        string orgB = await OrgSeeder.InsertAsync(_fixture.Store, $"orgB-{Guid.NewGuid():N}");
        string pkgA = await PackageSeeder.InsertAsync(_fixture.Store, orgA, "npm", "shared");
        string pkgB = await PackageSeeder.InsertAsync(_fixture.Store, orgB, "npm", "shared");
        string verA = await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgA, "1.0.0", Purl("1.0.0", "a"));
        await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgB, "1.0.0", Purl("1.0.0", "b"));
        string vulnId = await VulnerabilitySeeder.InsertVulnAsync(
            _fixture.Store, osvId: "MAL-2024-" + Guid.NewGuid().ToString("N")[..8], severity: null, cvssScore: null);
        await VulnerabilitySeeder.LinkAsync(_fixture.Store, verA, vulnId);

        var (itemsA, _) = await _repo.ListPaginatedAsync(new PackageListQuery(orgA, Limit: 10, Offset: 0, Ecosystem: "npm"));
        var (itemsB, _) = await _repo.ListPaginatedAsync(new PackageListQuery(orgB, Limit: 10, Offset: 0, Ecosystem: "npm"));
        Assert.True(Assert.Single(itemsA).HasMaliciousVersion);
        Assert.False(Assert.Single(itemsB).HasMaliciousVersion);

        Assert.True(Assert.Single(await _repo.GetVersionsAsync(pkgA)).IsMalicious);
        Assert.False(Assert.Single(await _repo.GetVersionsAsync(pkgB)).IsMalicious);
    }

    // ── Delete + proxy-purge ─────────────────────────────────────────────────

    [Fact]
    public async Task DeletePackageIfEmptyAsync_OnlyDeletes_WhenNoVersions()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "acme");
        await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgId, "1.0.0", Purl());

        Assert.False(await _repo.DeletePackageIfEmptyAsync(pkgId));   // version present → no-op
        Assert.NotNull(await _repo.GetByPurlNameAsync(orgId, "npm", "acme"));

        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync("DELETE FROM package_versions WHERE package_id = @id", new { id = pkgId });
        }

        Assert.True(await _repo.DeletePackageIfEmptyAsync(pkgId));
        Assert.Null(await _repo.GetByPurlNameAsync(orgId, "npm", "acme"));
    }

    [Fact]
    public async Task DeleteProxyVersionsForNameAsync_TouchesOnlyProxyRows_ReturnsBlobKeys()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "acme", isProxy: true);
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
