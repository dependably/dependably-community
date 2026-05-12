using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public class LicenseReviewQueueTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();

        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO orgs (id, slug) VALUES ('org1', 'org1'), ('org2', 'org2')");
        await conn.ExecuteAsync(
            """
            INSERT INTO packages (id, org_id, ecosystem, name, purl_name) VALUES
              ('p1', 'org1', 'pypi', 'a', 'a'),
              ('p2', 'org1', 'pypi', 'b', 'b'),
              ('p3', 'org2', 'pypi', 'c', 'c')
            """);
        await conn.ExecuteAsync(
            """
            INSERT INTO package_versions (id, package_id, version, purl, blob_key) VALUES
              ('pv1', 'p1', '1.0', 'pkg:pypi/a@1.0', 'blob1'),
              ('pv2', 'p1', '2.0', 'pkg:pypi/a@2.0', 'blob2'),
              ('pv3', 'p2', '1.0', 'pkg:pypi/b@1.0', 'blob3'),
              ('pv4', 'p3', '1.0', 'pkg:pypi/c@1.0', 'blob4')
            """);
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private LicenseRepository Repo() => new(_db);

    private async Task SeenAsync(string pvId, string spdx)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO package_version_licenses (id, package_version_id, license_spdx, source)
            VALUES (@id, @pv, @spdx, 'upstream')
            ON CONFLICT(package_version_id, license_spdx) DO NOTHING
            """,
            new { id = Guid.NewGuid().ToString("N"), pv = pvId, spdx });
    }

    [Fact]
    public async Task Empty_WhenNoLicensesObserved()
    {
        var queue = await Repo().GetReviewQueueAsync("org1", false);
        Assert.Empty(queue);
    }

    [Fact]
    public async Task Returns_LicensesNotOnEitherList()
    {
        await SeenAsync("pv1", "BSD-3-Clause");
        await SeenAsync("pv2", "ISC");

        var queue = await Repo().GetReviewQueueAsync("org1", false);

        Assert.Equal(2, queue.Count);
        Assert.Contains(queue, e => e.LicenseSpdx == "BSD-3-Clause");
        Assert.Contains(queue, e => e.LicenseSpdx == "ISC");
    }

    [Fact]
    public async Task Excludes_LicensesOnAllowlist()
    {
        await SeenAsync("pv1", "MIT");
        await SeenAsync("pv2", "BSD-3-Clause");
        await Repo().AddAllowlistAsync("org1", "MIT");

        var queue = await Repo().GetReviewQueueAsync("org1", false);
        Assert.Single(queue);
        Assert.Equal("BSD-3-Clause", queue[0].LicenseSpdx);
    }

    [Fact]
    public async Task Excludes_LicensesOnBlocklist()
    {
        await SeenAsync("pv1", "GPL-3.0-only");
        await SeenAsync("pv2", "MIT");
        await Repo().AddBlocklistAsync("org1", "GPL-3.0-only");

        var queue = await Repo().GetReviewQueueAsync("org1", false);
        Assert.Single(queue);
        Assert.Equal("MIT", queue[0].LicenseSpdx);
    }

    [Fact]
    public async Task Scopes_ByTenant_NoCrossLeak()
    {
        await SeenAsync("pv1", "MIT");           // org1
        await SeenAsync("pv4", "BSD-3-Clause");  // org2

        var queue1 = await Repo().GetReviewQueueAsync("org1", false);
        var queue2 = await Repo().GetReviewQueueAsync("org2", false);

        Assert.Single(queue1);
        Assert.Equal("MIT", queue1[0].LicenseSpdx);

        Assert.Single(queue2);
        Assert.Equal("BSD-3-Clause", queue2[0].LicenseSpdx);
    }

    [Fact]
    public async Task FlagsCompoundExpression()
    {
        await SeenAsync("pv1", "MIT OR Apache-2.0");
        await SeenAsync("pv2", "MIT");

        var queue = await Repo().GetReviewQueueAsync("org1", false);

        var compound = Assert.Single(queue, e => e.IsCompound);
        Assert.Equal("MIT OR Apache-2.0", compound.LicenseSpdx);

        var simple = Assert.Single(queue, e => e.LicenseSpdx == "MIT");
        Assert.False(simple.IsCompound);
    }

    [Fact]
    public async Task ExcludesDeprecatedByDefault_IncludesWhenAsked()
    {
        // GPL-3.0 (no -only/-or-later suffix) is in SPDX 3.28.0 as deprecated.
        await SeenAsync("pv1", "GPL-3.0");
        await SeenAsync("pv2", "MIT");

        var hidden = await Repo().GetReviewQueueAsync("org1", false);
        Assert.Single(hidden);
        Assert.Equal("MIT", hidden[0].LicenseSpdx);

        var shown = await Repo().GetReviewQueueAsync("org1", true);
        Assert.Equal(2, shown.Count);
        var dep = Assert.Single(shown, e => e.LicenseSpdx == "GPL-3.0");
        Assert.True(dep.IsDeprecated);
    }

    [Fact]
    public async Task AggregatesPackageCount_And_FirstSeen()
    {
        // MIT seen across two packages in org1 (p1 via pv1, p2 via pv3).
        await SeenAsync("pv1", "MIT");
        await SeenAsync("pv3", "MIT");

        var queue = await Repo().GetReviewQueueAsync("org1", false);

        var mit = Assert.Single(queue);
        Assert.Equal("MIT", mit.LicenseSpdx);
        Assert.Equal(2, mit.PackageCount);
        Assert.True(mit.FirstSeen != default);
    }
}
