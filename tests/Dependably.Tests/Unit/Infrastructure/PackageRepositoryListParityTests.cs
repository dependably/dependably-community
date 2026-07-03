using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// Result-parity coverage for the two-phase rewrite of
/// <see cref="PackageRepository.ListPaginatedAsync"/>. The plain-column sorts now page the
/// package ids first and hydrate the aggregate columns only for that page; these tests pin
/// that the rewrite returns the exact same rows, in the exact same order, with the exact same
/// aggregate values as (a) hand-computed truth over the seeded fixture and (b) the single
/// full-CTE query the aggregate-sort path still runs — across the default sort, an aggregate
/// sort, a search filter, and page 2.
/// </summary>
[Trait("Category", "Unit")]
public sealed class PackageRepositoryListParityTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;
    private readonly PackageRepository _repo;

    public PackageRepositoryListParityTests(InMemoryDbFixture fixture)
    {
        _fixture = fixture;
        _repo = new PackageRepository(_fixture.Store);
    }

    private static (string Id, string Name, string PurlName, string Ecosystem,
        int VersionCount, int Critical, int High, int Medium, int Low,
        long Downloads, bool Malicious, string LatestState) Key(Package p)
        => (p.Id, p.Name, p.PurlName, p.Ecosystem, p.VersionCount, p.CriticalCount,
            p.HighCount, p.MediumCount, p.LowCount, p.TotalDownloads, p.HasMaliciousVersion, p.LatestState);

    private async Task<string> SeedPackageAsync(
        string orgId, string name, string createdAt, long downloads,
        string[] severities, bool malicious)
    {
        string pkgId = Guid.NewGuid().ToString("N");
        string verId = Guid.NewGuid().ToString("N");
        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync("""
                INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy, created_at)
                VALUES (@id, @orgId, 'npm', @name, @name, 0, @createdAt)
                """, new { id = pkgId, orgId, name, createdAt });
            await conn.ExecuteAsync("""
                INSERT INTO package_versions
                    (id, package_id, version, purl, blob_key, filename, size_bytes, download_count, origin)
                VALUES (@id, @pkgId, '1.0.0', @purl, 'blob/key', 'key', 100, @downloads, 'uploaded')
                """, new { id = verId, pkgId, purl = $"pkg:npm/{Guid.NewGuid():N}/{name}@1.0.0", downloads });
        }

        foreach (string sev in severities)
        {
            string vid = await VulnerabilitySeeder.InsertVulnAsync(_fixture.Store, $"CVE-{Guid.NewGuid():N}", severity: sev);
            await VulnerabilitySeeder.LinkAsync(_fixture.Store, verId, vid);
        }

        if (malicious)
        {
            // MAL- advisories drive HasMaliciousVersion; the seeded one also carries a HIGH
            // severity so its HighCount contribution is part of the hand-computed truth.
            string vid = await VulnerabilitySeeder.InsertVulnAsync(_fixture.Store, $"MAL-{Guid.NewGuid():N}", severity: "HIGH");
            await VulnerabilitySeeder.LinkAsync(_fixture.Store, verId, vid);
        }

        return pkgId;
    }

    // Runs the single full-CTE query directly — the pre-change query shape the aggregate-sort
    // path still uses — as an independent parity oracle for the two-phase plain-column path.
    private async Task<List<Package>> RunFullReferenceAsync(
        string orgId, string? ecosystem, string? searchPattern, string sortBy, string sortDir, int limit, int offset)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        var rows = await conn.QueryAsync<Package>(
            PackageRepository.FullCteSqlFor(sortBy, sortDir),
            new { orgId, ecosystem, searchPattern, limit, offset });
        return rows.ToList();
    }

    private async Task<string> SeedFixtureAsync()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        // (name, createdAt, downloads, severities, malicious). Distinct names, created_at, and
        // download totals so every tested sort is a total order with no tiebreaker ambiguity.
        await SeedPackageAsync(orgId, "aa-alpha", "2026-06-01T00:00:00Z", 500, ["CRITICAL", "HIGH"], false);
        await SeedPackageAsync(orgId, "aa-beta", "2026-06-02T00:00:00Z", 25, ["LOW"], false);
        await SeedPackageAsync(orgId, "cc-gamma", "2026-06-03T00:00:00Z", 300, [], true);
        await SeedPackageAsync(orgId, "dd-delta", "2026-06-04T00:00:00Z", 50, [], false);
        await SeedPackageAsync(orgId, "ee-epsilon", "2026-06-05T00:00:00Z", 800, ["MEDIUM", "LOW"], false);
        await SeedPackageAsync(orgId, "ff-zeta", "2026-06-06T00:00:00Z", 999, [], false);
        await SeedPackageAsync(orgId, "gg-eta", "2026-06-07T00:00:00Z", 10, ["CRITICAL", "HIGH", "MEDIUM", "LOW"], false);
        await SeedPackageAsync(orgId, "hh-theta", "2026-06-08T00:00:00Z", 150, ["HIGH"], false);
        return orgId;
    }

    [Fact]
    public async Task DefaultSort_HydratesEveryAggregateColumn_MatchingHandComputedTruth()
    {
        string orgId = await SeedFixtureAsync();

        var (items, total) = await _repo.ListPaginatedAsync(new PackageListQuery(
            OrgId: orgId, Limit: 50, Offset: 0, Ecosystem: null, SortBy: "created", SortDir: "asc"));

        Assert.Equal(8, total);
        // created asc == seed order.
        Assert.Equal(
            ["aa-alpha", "aa-beta", "cc-gamma", "dd-delta", "ee-epsilon", "ff-zeta", "gg-eta", "hh-theta"],
            items.Select(p => p.Name).ToArray());

        // Hand-computed aggregate truth per package (name → C,H,M,L,downloads,malicious).
        var expected = new Dictionary<string, (int C, int H, int M, int L, long D, bool Mal)>
        {
            ["aa-alpha"] = (1, 1, 0, 0, 500, false),
            ["aa-beta"] = (0, 0, 0, 1, 25, false),
            ["cc-gamma"] = (0, 1, 0, 0, 300, true),
            ["dd-delta"] = (0, 0, 0, 0, 50, false),
            ["ee-epsilon"] = (0, 0, 1, 1, 800, false),
            ["ff-zeta"] = (0, 0, 0, 0, 999, false),
            ["gg-eta"] = (1, 1, 1, 1, 10, false),
            ["hh-theta"] = (0, 1, 0, 0, 150, false),
        };
        foreach (var p in items)
        {
            var (c, h, m, l, d, mal) = expected[p.Name];
            Assert.Equal(1, p.VersionCount);
            Assert.Equal(c, p.CriticalCount);
            Assert.Equal(h, p.HighCount);
            Assert.Equal(m, p.MediumCount);
            Assert.Equal(l, p.LowCount);
            Assert.Equal(d, p.TotalDownloads);
            Assert.Equal(mal, p.HasMaliciousVersion);
            Assert.Equal("unknown", p.LatestState);
        }

        // ... and byte-for-byte against the single full-CTE reference query.
        var reference = await RunFullReferenceAsync(orgId, null, null, "created", "asc", 50, 0);
        Assert.Equal(reference.Select(Key), items.Select(Key));
    }

    [Fact]
    public async Task DefaultSort_Page2_MatchesReferenceSlice()
    {
        string orgId = await SeedFixtureAsync();

        var (items, total) = await _repo.ListPaginatedAsync(new PackageListQuery(
            OrgId: orgId, Limit: 3, Offset: 3, Ecosystem: null, SortBy: "created", SortDir: "asc"));

        Assert.Equal(8, total);
        Assert.Equal(["dd-delta", "ee-epsilon", "ff-zeta"], items.Select(p => p.Name).ToArray());

        var reference = await RunFullReferenceAsync(orgId, null, null, "created", "asc", 3, 3);
        Assert.Equal(reference.Select(Key), items.Select(Key));
    }

    [Fact]
    public async Task AggregateSort_Downloads_MatchesReferenceAndHandComputedOrder()
    {
        string orgId = await SeedFixtureAsync();

        var (items, total) = await _repo.ListPaginatedAsync(new PackageListQuery(
            OrgId: orgId, Limit: 4, Offset: 0, Ecosystem: null, SortBy: "downloads", SortDir: "desc"));

        Assert.Equal(8, total);
        // downloads desc: 999, 800, 500, 300 → top 4.
        Assert.Equal(["ff-zeta", "ee-epsilon", "aa-alpha", "cc-gamma"], items.Select(p => p.Name).ToArray());

        var reference = await RunFullReferenceAsync(orgId, null, null, "downloads", "desc", 4, 0);
        Assert.Equal(reference.Select(Key), items.Select(Key));
    }

    [Fact]
    public async Task SearchFilter_WithNameSort_MatchesReference()
    {
        string orgId = await SeedFixtureAsync();

        var (items, total) = await _repo.ListPaginatedAsync(new PackageListQuery(
            OrgId: orgId, Limit: 50, Offset: 0, Ecosystem: null, Search: "aa-", SortBy: "name", SortDir: "asc"));

        Assert.Equal(2, total);
        Assert.Equal(["aa-alpha", "aa-beta"], items.Select(p => p.Name).ToArray());

        string searchPattern = "%aa-%";
        var reference = await RunFullReferenceAsync(orgId, null, searchPattern, "name", "asc", 50, 0);
        Assert.Equal(reference.Select(Key), items.Select(Key));
    }
}
