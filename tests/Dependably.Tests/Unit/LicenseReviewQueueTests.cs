using Dapper;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public class LicenseReviewQueueTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private LicenseNormalizer? _normalizer;

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
        // origin='uploaded': these represent hosted pushes (the SeenAsync helper attaches a
        // hosted-plane license fact to them). The proxy plane is exercised separately, through
        // ProxiedAsync's cache_artifact rows.
        await conn.ExecuteAsync(
            """
            INSERT INTO package_versions (id, package_id, version, purl, blob_key, origin) VALUES
              ('pv1', 'p1', '1.0', 'pkg:pypi/a@1.0', 'blob1', 'uploaded'),
              ('pv2', 'p1', '2.0', 'pkg:pypi/a@2.0', 'blob2', 'uploaded'),
              ('pv3', 'p2', '1.0', 'pkg:pypi/b@1.0', 'blob3', 'uploaded'),
              ('pv4', 'p3', '1.0', 'pkg:pypi/c@1.0', 'blob4', 'uploaded')
            """);
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private LicenseRepository Repo() => new(
        _db, TimeProvider.System,
        _normalizer ??= new LicenseNormalizer(_db, NullLogger<LicenseNormalizer>.Instance));

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

    /// <summary>
    /// Seeds a proxied (global cache-plane) artifact: a cache_artifact row, a
    /// tenant_artifact_access grant for <paramref name="orgId"/>, and a cache-plane
    /// license row (owner_kind='cache_artifact'). Mirrors the dual-write path.
    /// </summary>
    private async Task ProxiedAsync(
        string orgId, string ecosystem, string name, string version, string spdx)
    {
        await using var conn = await _db.OpenAsync();
        // Reuse an existing cache_artifact for the same coordinate (UNIQUE on the coordinate),
        // otherwise create one.
        string caId = await conn.ExecuteScalarAsync<string>(
            "SELECT id FROM cache_artifact WHERE ecosystem = @ecosystem AND name = @name AND version = @version",
            new { ecosystem, name, version }) ?? "";
        if (string.IsNullOrEmpty(caId))
        {
            caId = Guid.NewGuid().ToString("N");
            await conn.ExecuteAsync(
                """
                INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash)
                VALUES (@id, @ecosystem, @name, @version, @filename, @blobKey, @hash)
                """,
                new
                {
                    id = caId,
                    ecosystem,
                    name,
                    version,
                    filename = $"{name}-{version}",
                    blobKey = $"proxy/{caId}",
                    hash = caId
                });
        }

        await conn.ExecuteAsync(
            """
            INSERT INTO tenant_artifact_access (org_id, cache_artifact_id)
            VALUES (@orgId, @caId)
            ON CONFLICT(org_id, cache_artifact_id) DO NOTHING
            """,
            new { orgId, caId });

        await conn.ExecuteAsync(
            """
            INSERT INTO package_version_licenses
                (id, cache_artifact_id, owner_kind, license_spdx, source)
            VALUES (@id, @caId, 'cache_artifact', @spdx, 'upstream')
            ON CONFLICT(cache_artifact_id, license_spdx) DO NOTHING
            """,
            new { id = Guid.NewGuid().ToString("N"), caId, spdx });
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
    public async Task SplitsCompoundExpression_IntoIndividualLeaves()
    {
        // pv1 (pypi:a) is licensed under a compound expression; pv3 (pypi:b) under bare MIT.
        await SeenAsync("pv1", "MIT OR Apache-2.0");
        await SeenAsync("pv3", "MIT");

        var queue = await Repo().GetReviewQueueAsync("org1", false);

        // The compound splits into two individually-actionable leaves — no opaque compound row.
        Assert.Equal(2, queue.Count);

        var mit = Assert.Single(queue, e => e.LicenseSpdx == "MIT");
        Assert.Equal(2, mit.PackageCount); // observed on pypi:a and pypi:b

        var apache = Assert.Single(queue, e => e.LicenseSpdx == "Apache-2.0");
        Assert.Equal(1, apache.PackageCount); // only pypi:a
    }

    [Fact]
    public async Task CollapsesNameVariant_OntoCanonicalId()
    {
        // Two different packages carry the same license expressed two ways — they collapse onto
        // the canonical Apache-2.0 id and the distinct package count sums across both.
        await SeenAsync("pv1", "Apache License 2.0"); // pypi:a
        await SeenAsync("pv3", "Apache-2.0");          // pypi:b

        var queue = await Repo().GetReviewQueueAsync("org1", false);

        var apache = Assert.Single(queue);
        Assert.Equal("Apache-2.0", apache.LicenseSpdx);
        Assert.Equal(2, apache.PackageCount);
    }

    [Fact]
    public async Task Excludes_AllowlistedAndBlocklisted_Leaves()
    {
        // Leaves already on either list must not surface — even when observed inside a compound.
        await SeenAsync("pv1", "MIT OR GPL-3.0-only"); // pypi:a
        await SeenAsync("pv3", "ISC");                  // pypi:b
        await Repo().AddAllowlistAsync("org1", "MIT");
        await Repo().AddBlocklistAsync("org1", "GPL-3.0-only");

        var queue = await Repo().GetReviewQueueAsync("org1", false);

        var entry = Assert.Single(queue);
        Assert.Equal("ISC", entry.LicenseSpdx);
    }

    [Fact]
    public async Task ObservedDeprecatedLeaf_IsAlwaysSurfaced()
    {
        // GPL-3.0 (no -only/-or-later suffix) is in SPDX 3.28.0 as deprecated. The normalizer
        // does not remap it, so a real observation must always appear to be actionable.
        await SeenAsync("pv1", "GPL-3.0");
        await SeenAsync("pv2", "MIT");

        var queue = await Repo().GetReviewQueueAsync("org1", false);
        Assert.Equal(2, queue.Count);

        var dep = Assert.Single(queue, e => e.LicenseSpdx == "GPL-3.0");
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

    [Fact]
    public async Task Includes_ProxiedOnlyLicense_FromCachePlane()
    {
        // No hosted license rows at all — only a proxied (cache-plane) artifact carries this
        // license. Before the UNION arm was added this license was invisible to the queue.
        await ProxiedAsync("org1", "npm", "left-pad", "1.3.0", "WTFPL");

        var queue = await Repo().GetReviewQueueAsync("org1", false);

        var entry = Assert.Single(queue);
        Assert.Equal("WTFPL", entry.LicenseSpdx);
        Assert.Equal(1, entry.PackageCount);
    }

    [Fact]
    public async Task CachePlane_ScopedByTenant_NoCrossLeak()
    {
        // A cache artifact accessed only by org2 must not surface for org1, even though the
        // cache_artifact row itself is global.
        await ProxiedAsync("org2", "npm", "left-pad", "1.3.0", "WTFPL");

        var queue1 = await Repo().GetReviewQueueAsync("org1", false);
        var queue2 = await Repo().GetReviewQueueAsync("org2", false);

        Assert.Empty(queue1);
        Assert.Single(queue2, e => e.LicenseSpdx == "WTFPL");
    }

    [Fact]
    public async Task CrossPlaneMerge_SameCoordinate_CountsOnce()
    {
        // p1 in org1 is pypi:a. Attach MIT on the hosted plane (pv1) AND on the proxy plane
        // for the same ecosystem:name coordinate — the queue must merge to ONE row with a
        // distinct package count of 1 (the same coordinate, not two).
        await SeenAsync("pv1", "MIT");
        await ProxiedAsync("org1", "pypi", "a", "3.0", "MIT");

        var queue = await Repo().GetReviewQueueAsync("org1", false);

        var mit = Assert.Single(queue, e => e.LicenseSpdx == "MIT");
        Assert.Equal(1, mit.PackageCount);
    }

    [Fact]
    public async Task Excludes_AllowlistedAndBlocklisted_CachePlaneLicense()
    {
        await ProxiedAsync("org1", "npm", "a-pkg", "1.0", "MIT");
        await ProxiedAsync("org1", "npm", "b-pkg", "1.0", "GPL-3.0-only");
        await ProxiedAsync("org1", "npm", "c-pkg", "1.0", "ISC");
        await Repo().AddAllowlistAsync("org1", "MIT");
        await Repo().AddBlocklistAsync("org1", "GPL-3.0-only");

        var queue = await Repo().GetReviewQueueAsync("org1", false);

        var entry = Assert.Single(queue);
        Assert.Equal("ISC", entry.LicenseSpdx);
    }

    [Fact]
    public async Task PopulatesNameAndCopyleft_ForSeededId_AndDefaultsForCustom()
    {
        // MIT is in the seeded spdx_license table (name + copyleft populated).
        await SeenAsync("pv1", "MIT");
        // A custom identifier absent from the SPDX list: Name is NULL, Copyleft defaults.
        await SeenAsync("pv2", "LicenseRef-Acme-Proprietary");

        var queue = await Repo().GetReviewQueueAsync("org1", false);

        var mit = Assert.Single(queue, e => e.LicenseSpdx == "MIT");
        Assert.Equal("MIT License", mit.Name);
        Assert.Equal("permissive", mit.Copyleft);

        var custom = Assert.Single(queue, e => e.LicenseSpdx == "LicenseRef-Acme-Proprietary");
        Assert.Null(custom.Name);
        Assert.Equal("unclassified", custom.Copyleft);
    }
}
