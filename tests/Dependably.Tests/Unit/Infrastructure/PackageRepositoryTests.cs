using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Time.Testing;

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
    public async Task InsertPackageSql_LoserRaceAgainstSeededCoordinate_NoOpsAndConvergesOnWinner()
    {
        // Pins the PRODUCTION statement GetOrCreateAsync actually executes
        // (PackageRepository.InsertPackageSql), not a test-owned copy that could silently drift.
        // Reproduces the loser's exact branch: a second INSERT lands at a coordinate a winner row
        // already occupies. If ON CONFLICT (org_id, ecosystem, purl_name) DO NOTHING is ever
        // dropped from the const, this INSERT throws SqliteException instead of no-op'ing, and
        // the assertion below on `affected` never runs — the test goes red.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        string winnerId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "raced", purlName: "raced");

        string loserId = Guid.NewGuid().ToString("N");
        await using var conn = await _fixture.Store.OpenAsync();
        int affected = await conn.ExecuteAsync(
            PackageRepository.InsertPackageSql,
            new { id = loserId, orgId, ecosystem = "npm", name = "raced", purlName = "raced", isProxy = 0 });

        Assert.Equal(0, affected);

        var converged = await _repo.GetOrCreateAsync(orgId, "npm", "raced", "raced", isProxy: false);
        Assert.Equal(winnerId, converged.Id);
        Assert.NotEqual(loserId, converged.Id);

        long count = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM packages WHERE org_id = @orgId AND ecosystem = 'npm' AND purl_name = 'raced'",
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
            UpstreamIntegrityAlgorithm: "sha512-sri", Origin: "uploaded"));

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
            FirstFetch: true, ChecksumSha1: "abc123def456", Origin: "uploaded"));

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
            FirstFetch: true, PublishedAt: publishedAt, Origin: "uploaded"));

        Assert.Equal(publishedAt, created.PublishedAt);

        var fetched = await _repo.GetVersionByIdAsync(orgId, created.Id);
        Assert.NotNull(fetched);
        Assert.Equal(publishedAt, fetched!.PublishedAt);

        var list = await _repo.GetVersionsAsync(pkgId);
        Assert.Equal(publishedAt, list[0].PublishedAt);
    }

    [Fact]
    public async Task UpdateVersionsBehindAsync_RoundTripsThroughEveryReadSurface()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "acme");
        string purl = Purl();

        var created = await _repo.CreateVersionAsync(new NewPackageVersion(
            pkgId, "1.0.0", purl, "blob/key", 100, "sha256hex", FirstFetch: false, Origin: "uploaded"));
        Assert.Null(created.VersionsBehind); // unwritten default — unknown, not 0

        await _repo.UpdateVersionsBehindAsync(created.Id, 4);

        Assert.Equal(4, (await _repo.GetVersionByIdAsync(orgId, created.Id))!.VersionsBehind);
        Assert.Equal(4, (await _repo.GetVersionAsync(pkgId, "1.0.0"))!.VersionsBehind);
        Assert.Equal(4, (await _repo.GetVersionByBlobKeyAsync(orgId, "blob/key"))!.VersionsBehind);
        Assert.Equal(4, Assert.Single(await _repo.GetVersionsAsync(pkgId)).VersionsBehind);

        // Writing null resets to unknown rather than leaving a stale count behind.
        await _repo.UpdateVersionsBehindAsync(created.Id, null);
        Assert.Null((await _repo.GetVersionByIdAsync(orgId, created.Id))!.VersionsBehind);
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

    [Fact]
    public async Task UpdateVersionForOverwriteAsync_StampsUpdatedAt_PreservesCreatedAt_AndClearsProvenance()
    {
        var clock = TestTime.Frozen();
        var repo = new PackageRepository(_fixture.Store, time: clock);

        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "acme");
        string verId = await PackageSeeder.InsertVersionAsync(
            _fixture.Store, pkgId, "1.0.0", Purl(), blobKey: $"old-{Guid.NewGuid():N}", sizeBytes: 100, checksumSha256: "old-sha");

        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                """
                UPDATE package_versions
                   SET provenance_status = 'verified', provenance_signer = 'trust-anchor-1'
                 WHERE id = @id
                """,
                new { id = verId });
        }

        var before = (await repo.GetVersionByIdAsync(orgId, verId))!;
        Assert.Null(before.UpdatedAt);
        Assert.Equal("verified", before.ProvenanceStatus);

        clock.Advance(TimeSpan.FromHours(3));

        await repo.UpdateVersionForOverwriteAsync(verId, "new-blob", 200, "new-sha", "uploaded", sha1: "new-sha1");

        var after = (await repo.GetVersionByIdAsync(orgId, verId))!;
        Assert.Equal("new-blob", after.BlobKey);
        Assert.Equal(200, after.SizeBytes);
        Assert.Equal("new-sha", after.ChecksumSha256);
        Assert.Equal("new-sha1", after.ChecksumSha1);
        Assert.Equal(before.CreatedAt, after.CreatedAt);
        Assert.Equal(clock.GetUtcNow(), after.UpdatedAt);
        Assert.NotEqual(after.CreatedAt, after.UpdatedAt);
        Assert.Null(after.ProvenanceStatus);
        Assert.Null(after.ProvenanceSigner);
    }

    /// <summary>
    /// A same-version re-push must refresh the stored install manifest and integrity SRI to
    /// the new artefact's values, and clear them when the new push carries none — a stale
    /// manifest or integrity describing the replaced bytes must never survive an overwrite.
    /// </summary>
    [Fact]
    public async Task UpdateVersionForOverwriteAsync_RefreshesManifestAndIntegrity_AndClearsWhenAbsent()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "acme");
        string verId = await PackageSeeder.InsertVersionAsync(
            _fixture.Store, pkgId, "1.0.0", Purl(), blobKey: $"old-{Guid.NewGuid():N}", sizeBytes: 100, checksumSha256: "old-sha");

        await _repo.UpdateVersionForOverwriteAsync(verId, "new-blob", 200, "new-sha", "uploaded",
            sha1: "new-sha1", integrityValue: "sha512-new==", integrityAlgorithm: "sha512-sri",
            manifestJson: """{"dependencies":{"yaml":"^2.0.0"}}""");

        var v = (await _repo.GetVersionByIdAsync(orgId, verId))!;
        Assert.Equal("sha512-new==", v.UpstreamIntegrityValue);
        Assert.Equal("sha512-sri", v.UpstreamIntegrityAlgorithm);
        Assert.Equal("""{"dependencies":{"yaml":"^2.0.0"}}""", v.ManifestJson);

        // A subsequent overwrite with no manifest/integrity clears the stored values.
        await _repo.UpdateVersionForOverwriteAsync(verId, "new-blob-2", 300, "new-sha-2", "uploaded", sha1: null);

        var cleared = (await _repo.GetVersionByIdAsync(orgId, verId))!;
        Assert.Null(cleared.UpstreamIntegrityValue);
        Assert.Null(cleared.UpstreamIntegrityAlgorithm);
        Assert.Null(cleared.ManifestJson);
    }

    // ── Pagination ───────────────────────────────────────────────────────────

    [Fact]
    public async Task ListPaginatedAsync_Search_EscapesWildcards_AndOnlyMatchesLiteral()
    {
        // "ev_il" is matched as a literal substring: the '_' is escaped, so it must not act as
        // the SQL single-character wildcard and pull in "evxil". LOWER()-folding the pattern must
        // not disturb the ESCAPE '\' handling either.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "ev_il");
        await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "evxil");

        var (items, total) = await _repo.ListPaginatedAsync(new PackageListQuery(
            OrgId: orgId, Limit: 50, Offset: 0, Ecosystem: "npm", Search: "ev_il"));

        Assert.Equal(1, total);
        Assert.Single(items);
        Assert.Equal("ev_il", items[0].Name);
    }

    /// <summary>
    /// Search matches a substring of the name, not just its prefix. Package names carry an
    /// ecosystem-specific prefix the user does not type — npm scopes and Maven
    /// groupId:artifactId coordinates — so a prefix-anchored pattern would make the npm search
    /// protocol, the Cargo search protocol, and the management typeahead all return nothing for
    /// the term a user actually types. The leading wildcard is a product requirement; this pins
    /// it against being "optimized" away in pursuit of an index that cannot exist.
    /// </summary>
    [Theory]
    [InlineData("core", "@babel/core")]              // npm scope: user types the bare package name
    [InlineData("jackson-databind", "com.fasterxml.jackson.core:jackson-databind")] // maven artifactId
    [InlineData("databind", "com.fasterxml.jackson.core:jackson-databind")]         // maven, mid-artifact
    public async Task ListPaginatedAsync_Search_MatchesMidName_NotOnlyPrefix(string term, string packageName)
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", packageName);
        await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "unrelated-package");

        var (items, total) = await _repo.ListPaginatedAsync(new PackageListQuery(
            OrgId: orgId, Limit: 50, Offset: 0, Ecosystem: "npm", Search: term));

        Assert.Equal(1, total);
        Assert.Equal(packageName, Assert.Single(items).Name);
    }

    /// <summary>
    /// Search folds case, and does so identically on both providers. SQLite's LIKE folds ASCII
    /// case on its own but Postgres's does not, so the predicate LOWER()s both sides; without
    /// that, the same search returns different rows depending on DB_PROVIDER. This test pins the
    /// behaviour on SQLite — <c>PostgresQuerySmokeTests</c> runs the same predicate live on PG.
    /// </summary>
    [Theory]
    [InlineData("REQUESTS")]
    [InlineData("Requests")]
    [InlineData("requests")]
    public async Task ListPaginatedAsync_Search_IsCaseInsensitive(string term)
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "Python-Requests");

        var (items, total) = await _repo.ListPaginatedAsync(new PackageListQuery(
            OrgId: orgId, Limit: 50, Offset: 0, Ecosystem: "npm", Search: term));

        Assert.Equal(1, total);
        Assert.Equal("Python-Requests", Assert.Single(items).Name);
    }

    /// <summary>
    /// The search COUNT must stay bounded to the tenant's own rows via idx_packages_org_ecosystem.
    /// A substring LIKE is not sargable — no B-tree can range-bound a leading wildcard on either
    /// provider — so the org bound is the only thing standing between a search request and a scan
    /// of every package on the instance. This plans the exact production CountSql string and fails
    /// if the org bound is ever lost (e.g. a predicate rewrite that wraps org_id in a function, or
    /// a dropped index), which is the resource-consumption invariant a semantics test cannot pin.
    /// </summary>
    [Fact]
    public async Task CountSql_SearchPlan_StaysBoundedByTheOrgIndex()
    {
        await using var conn = await _fixture.Store.OpenAsync();
        var rows = await conn.QueryAsync(
            "EXPLAIN QUERY PLAN " + PackageRepository.CountSql,
            new { orgId = "org-plan-probe", ecosystem = (string?)null, searchPattern = "%core%" });

        string plan = string.Join("\n", rows.Select(r => (string)r.detail));

        // Bounded by org through the index: "SEARCH p USING INDEX idx_packages_org_ecosystem
        // (org_id=?)". A plan that reads "SCAN p" would mean every package on the instance is
        // examined for one tenant's search.
        Assert.Contains("idx_packages_org_ecosystem", plan, StringComparison.Ordinal);
        Assert.Contains("org_id=?", plan, StringComparison.Ordinal);
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
        // v1 is proxy-cached (download count tracked in tenant_artifact_access);
        // v2 is uploaded (download count tracked in package_versions). The aggregated
        // TotalDownloads must sum both planes.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "acme");
        // Proxy plane: seed cache_artifact + tenant_artifact_access with download_count=7.
        string caId = Guid.NewGuid().ToString("N");
        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync("""
                INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash)
                VALUES (@id, 'npm', 'acme', '1.0.0', 'acme-1.0.0.tgz', 'proxy/k1', 'h1')
                """, new { id = caId });
            await conn.ExecuteAsync(
                "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id, download_count) VALUES (@orgId, @caId, 7)",
                new { orgId, caId });
        }
        // Uploaded plane: version in package_versions with download_count=5.
        string v2 = await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgId, "2.0.0", Purl("2.0.0"), origin: "uploaded");
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
        // Proxy-cached versions live in cache_artifact + tenant_artifact_access; the LatestState
        // query checks that table for the upstream-latest version.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "latestproxy", isProxy: true);
        await _repo.UpdateUpstreamLatestAsync(pkgId, "2.0.0");
        // Seed both 1.0.0 and 2.0.0 in cache_artifact so the package has proxy entries.
        await using (var conn = await _fixture.Store.OpenAsync())
        {
            string ca1 = Guid.NewGuid().ToString("N");
            string ca2 = Guid.NewGuid().ToString("N");
            await conn.ExecuteAsync("""
                INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash)
                VALUES (@id, 'npm', 'latestproxy', '1.0.0', 'latestproxy-1.0.0.tgz', 'proxy/lp1', 'h1'),
                       (@id2, 'npm', 'latestproxy', '2.0.0', 'latestproxy-2.0.0.tgz', 'proxy/lp2', 'h2')
                """, new { id = ca1, id2 = ca2 });
            await conn.ExecuteAsync("""
                INSERT INTO tenant_artifact_access (org_id, cache_artifact_id)
                VALUES (@orgId, @ca1), (@orgId, @ca2)
                """, new { orgId, ca1, ca2 });
        }

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
    public async Task ListPaginatedAsync_LatestState_CurrentWhenUpstreamLatestIsUploaded()
    {
        // An uploaded version at upstream-latest counts as "current" — the tenant has that
        // version available regardless of whether it came from the proxy cache or a publish.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "uploadedlatest", isProxy: true);
        await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgId, "2.0.0", Purl("2.0.0", "uploadedlatest"), origin: "uploaded");
        await _repo.UpdateUpstreamLatestAsync(pkgId, "2.0.0");

        var (items, _) = await _repo.ListPaginatedAsync(new PackageListQuery(orgId, Limit: 10, Offset: 0, Ecosystem: "npm"));

        Assert.Equal("current", Assert.Single(items).LatestState);
    }

    // The package-detail query (GetByPurlNameAsync) drives the per-package upstream-currency
    // banner. It must compute LatestState identically to the packages-list query above —
    // otherwise the detail banner and the list "Latest" indicator disagree. The proxy-cached
    // case is the one that regressed: npm/PyPI proxy artifacts live in the global plane
    // (cache_artifact + tenant_artifact_access), not package_versions, so a detail query that
    // only checked package_versions reported the package "stale" while the version was cached.

    [Fact]
    public async Task GetByPurlNameAsync_LatestState_UnknownWhenNoUpstreamBaseline()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "detailunknown", isProxy: true);

        var pkg = await _repo.GetByPurlNameAsync(orgId, "npm", "detailunknown");

        Assert.NotNull(pkg);
        Assert.Equal("unknown", pkg.LatestState);
        Assert.Null(pkg.UpstreamLatestVersion);
    }

    [Fact]
    public async Task GetByPurlNameAsync_LatestState_CurrentWhenUpstreamLatestIsProxyCached()
    {
        // Proxy-cached versions live in cache_artifact + tenant_artifact_access; the detail
        // LatestState query must check that plane for the upstream-latest version.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "detailproxy", isProxy: true);
        await _repo.UpdateUpstreamLatestAsync(pkgId, "2.0.0");
        await using (var conn = await _fixture.Store.OpenAsync())
        {
            string ca = Guid.NewGuid().ToString("N");
            await conn.ExecuteAsync("""
                INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash)
                VALUES (@id, 'npm', 'detailproxy', '2.0.0', 'detailproxy-2.0.0.tgz', 'proxy/dp2', 'h2')
                """, new { id = ca });
            await conn.ExecuteAsync("""
                INSERT INTO tenant_artifact_access (org_id, cache_artifact_id)
                VALUES (@orgId, @ca)
                """, new { orgId, ca });
        }

        var pkg = await _repo.GetByPurlNameAsync(orgId, "npm", "detailproxy");

        Assert.NotNull(pkg);
        Assert.Equal("current", pkg.LatestState);
        Assert.Equal("2.0.0", pkg.UpstreamLatestVersion);
    }

    [Fact]
    public async Task GetByPurlNameAsync_LatestState_StaleWhenUpstreamLatestNotCached()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "detailstale", isProxy: true);
        await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgId, "1.0.0", Purl("1.0.0", "detailstale"), origin: "uploaded");
        // Upstream's latest (3.0.0) is newer than anything cached locally.
        await _repo.UpdateUpstreamLatestAsync(pkgId, "3.0.0");

        var pkg = await _repo.GetByPurlNameAsync(orgId, "npm", "detailstale");

        Assert.NotNull(pkg);
        Assert.Equal("stale", pkg.LatestState);
    }

    [Fact]
    public async Task GetByPurlNameAsync_LatestState_CurrentWhenUpstreamLatestIsUploaded()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "detailuploaded", isProxy: true);
        await PackageSeeder.InsertVersionAsync(_fixture.Store, pkgId, "2.0.0", Purl("2.0.0", "detailuploaded"), origin: "uploaded");
        await _repo.UpdateUpstreamLatestAsync(pkgId, "2.0.0");

        var pkg = await _repo.GetByPurlNameAsync(orgId, "npm", "detailuploaded");

        Assert.NotNull(pkg);
        Assert.Equal("current", pkg.LatestState);
    }

    // ── AbandonedState (computed in C# against the injected TimeProvider, not SQL) ─────────────
    // Offsets are deliberately far from the 365-day boundary (400/300 days) rather than exactly
    // .AddDays(-365) — a boundary-exact seed drifts across leap years and makes the derivation
    // flaky depending on which year the frozen "now" falls in.

    [Fact]
    public async Task ListPaginatedAsync_AbandonedState_UnknownWhenNoPublishedAtKnown()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "nopublish", isProxy: true);
        // A version baseline exists, but its publish timestamp is unknown (e.g. air-gapped or an
        // ecosystem whose metadata doesn't carry one) — must render "unknown", never "abandoned".
        await _repo.UpdateUpstreamLatestAsync(pkgId, "1.0.0", publishedAt: null);

        var (items, _) = await _repo.ListPaginatedAsync(new PackageListQuery(orgId, Limit: 10, Offset: 0, Ecosystem: "npm"));

        Assert.Equal("unknown", Assert.Single(items).AbandonedState);
    }

    [Fact]
    public async Task ListPaginatedAsync_AbandonedState_ActiveWhenPublishedRecently()
    {
        var clock = TestTime.Frozen();
        var repo = new PackageRepository(_fixture.Store, time: clock);
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "recent", isProxy: true);
        await repo.UpdateUpstreamLatestAsync(pkgId, "1.0.0", publishedAt: clock.GetUtcNow().AddDays(-300));

        var (items, _) = await repo.ListPaginatedAsync(new PackageListQuery(orgId, Limit: 10, Offset: 0, Ecosystem: "npm"));

        Assert.Equal("active", Assert.Single(items).AbandonedState);
    }

    [Fact]
    public async Task ListPaginatedAsync_AbandonedState_AbandonedWhenPublishedOverAYearAgo()
    {
        var clock = TestTime.Frozen();
        var repo = new PackageRepository(_fixture.Store, time: clock);
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "stale-abandoned", isProxy: true);
        await repo.UpdateUpstreamLatestAsync(pkgId, "1.0.0", publishedAt: clock.GetUtcNow().AddDays(-400));

        var (items, _) = await repo.ListPaginatedAsync(new PackageListQuery(orgId, Limit: 10, Offset: 0, Ecosystem: "npm"));

        Assert.Equal("abandoned", Assert.Single(items).AbandonedState);
    }

    // A single list call spanning packages in every AbandonedState bucket — the "some succeed,
    // some fail (are stale), some are unknown, in the same call" batch scenario, not just an
    // all-abandoned or all-active fixture.
    [Fact]
    public async Task ListPaginatedAsync_AbandonedState_MixedBatch_ComputesIndependentlyPerPackage()
    {
        var clock = TestTime.Frozen();
        var repo = new PackageRepository(_fixture.Store, time: clock);
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        string abandonedId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "mix-abandoned", isProxy: true);
        string activeId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "mix-active", isProxy: true);
        string unknownId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "mix-unknown", isProxy: true);
        await repo.UpdateUpstreamLatestAsync(abandonedId, "1.0.0", publishedAt: clock.GetUtcNow().AddDays(-400));
        await repo.UpdateUpstreamLatestAsync(activeId, "1.0.0", publishedAt: clock.GetUtcNow().AddDays(-300));
        // unknownId gets no upstream_latest_version/published_at baseline at all.

        var (items, total) = await repo.ListPaginatedAsync(new PackageListQuery(orgId, Limit: 10, Offset: 0, Ecosystem: "npm"));

        Assert.Equal(3, total);
        Assert.Equal("abandoned", items.Single(p => p.Id == abandonedId).AbandonedState);
        Assert.Equal("active", items.Single(p => p.Id == activeId).AbandonedState);
        Assert.Equal("unknown", items.Single(p => p.Id == unknownId).AbandonedState);
    }

    [Fact]
    public async Task GetByPurlNameAsync_AbandonedState_MatchesListPaginatedAsyncDerivation()
    {
        // The package-detail query must agree with the packages-list query on the same
        // derivation — otherwise the detail badge and the list badge disagree for one package.
        var clock = TestTime.Frozen();
        var repo = new PackageRepository(_fixture.Store, time: clock);
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", "detailabandoned", isProxy: true);
        await repo.UpdateUpstreamLatestAsync(pkgId, "1.0.0", publishedAt: clock.GetUtcNow().AddDays(-400));

        var pkg = await repo.GetByPurlNameAsync(orgId, "npm", "detailabandoned");

        Assert.NotNull(pkg);
        Assert.Equal("abandoned", pkg.AbandonedState);
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

    [Fact]
    public async Task ListPaginatedAsync_SeverityCounts_And_Malicious_SpanProxyCachePlane()
    {
        // Proxy packages keep a per-tenant packages row but their versions and vuln links live on
        // the global cache plane (cache_artifact + tenant_artifact_access; owner_kind='cache_artifact').
        // The list's severity counts and malicious flag must read that plane, not just package_versions.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        string name = "cacheplane-" + Guid.NewGuid().ToString("N")[..8];
        await PackageSeeder.InsertAsync(_fixture.Store, orgId, "npm", name, isProxy: true);
        string caId = Guid.NewGuid().ToString("N");
        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash)
                VALUES (@caId, 'npm', @name, '1.0.0', @fn, @bk, @ch)
                """,
                new { caId, name, fn = name + "-1.0.0.tgz", bk = "proxy/" + caId, ch = "h-" + caId });
            await conn.ExecuteAsync(
                "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES (@orgId, @caId)",
                new { orgId, caId });
        }
        string crit = await VulnerabilitySeeder.InsertVulnAsync(
            _fixture.Store, osvId: "GHSA-" + Guid.NewGuid().ToString("N")[..8], severity: "CRITICAL");
        string mal = await VulnerabilitySeeder.InsertVulnAsync(
            _fixture.Store, osvId: "MAL-2024-" + Guid.NewGuid().ToString("N")[..8], severity: null, cvssScore: null);
        await VulnerabilitySeeder.LinkToCacheArtifactAsync(_fixture.Store, caId, crit);
        await VulnerabilitySeeder.LinkToCacheArtifactAsync(_fixture.Store, caId, mal);

        var (items, _) = await _repo.ListPaginatedAsync(
            new PackageListQuery(orgId, Limit: 10, Offset: 0, Ecosystem: "npm"));

        var pkg = Assert.Single(items);
        Assert.Equal(1, pkg.CriticalCount);   // CRITICAL advisory on the cache plane surfaces in the list
        Assert.True(pkg.HasMaliciousVersion); // MAL- advisory on the cache plane flips the flag
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

    /// <summary>
    /// Regression: a proxy-only package (is_proxy) never has package_versions rows, so the
    /// emptiness check must also consult the cache plane (tenant_artifact_access joined to
    /// cache_artifact by ecosystem+purl_name) — otherwise the packages row is GC'd the moment its
    /// last package_versions row is gone even while this org still has other cache-plane versions
    /// of the same package, silently re-creating the "0 versions" symptom this method guards
    /// against.
    /// </summary>
    [Fact]
    public async Task DeletePackageIfEmptyAsync_CachePlaneVersionPresent_DoesNotDelete()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(
            _fixture.Store, orgId, "oci", "library/ubuntu", isProxy: true, purlName: "library/ubuntu");

        string caId = Guid.NewGuid().ToString("N");
        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash, size_bytes) " +
                "VALUES (@id, 'oci', 'library/ubuntu', 'sha256:aa', 'manifest', 'oci/sha256/aa', 'aa', 100)",
                new { id = caId });
            await conn.ExecuteAsync(
                "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES (@orgId, @caId)",
                new { orgId, caId });
        }

        // No package_versions rows at all — a proxy-only package — but the cache plane still has
        // a live version, so the row must survive.
        Assert.False(await _repo.DeletePackageIfEmptyAsync(pkgId));
        Assert.NotNull(await _repo.GetByPurlNameAsync(orgId, "oci", "library/ubuntu"));

        // Once the cache-plane version is also gone, the package is GC-eligible.
        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "DELETE FROM tenant_artifact_access WHERE org_id = @orgId AND cache_artifact_id = @caId",
                new { orgId, caId });
        }
        Assert.True(await _repo.DeletePackageIfEmptyAsync(pkgId));
        Assert.Null(await _repo.GetByPurlNameAsync(orgId, "oci", "library/ubuntu"));
    }

    /// <summary>
    /// A cache-plane version under a DIFFERENT package (different purl_name, or a different org
    /// entirely) must never block this package's GC — the cache-plane NOT EXISTS check is scoped
    /// to this row's own (org_id, ecosystem, purl_name), not a blanket "cache_artifact has any
    /// row for this ecosystem" check.
    /// </summary>
    [Fact]
    public async Task DeletePackageIfEmptyAsync_CachePlaneVersionUnderDifferentPackage_StillDeletes()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(
            _fixture.Store, orgId, "oci", "library/redis", isProxy: true, purlName: "library/redis");
        await PackageSeeder.InsertAsync(
            _fixture.Store, orgId, "oci", "library/postgres", isProxy: true, purlName: "library/postgres");

        // A cache-plane version for a DIFFERENT purl_name in the SAME org — irrelevant to pkgId.
        string otherCaId = Guid.NewGuid().ToString("N");
        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash, size_bytes) " +
                "VALUES (@id, 'oci', 'library/postgres', 'sha256:bb', 'manifest', 'oci/sha256/bb', 'bb', 100)",
                new { id = otherCaId });
            await conn.ExecuteAsync(
                "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES (@orgId, @caId)",
                new { orgId, caId = otherCaId });
        }

        Assert.True(await _repo.DeletePackageIfEmptyAsync(pkgId));
        Assert.Null(await _repo.GetByPurlNameAsync(orgId, "oci", "library/redis"));
        // The unrelated package's cache-plane version is untouched.
        Assert.NotNull(await _repo.GetByPurlNameAsync(orgId, "oci", "library/postgres"));
    }

    // ── ReleaseOciDigestClaimAsync ──────────────────────────────────────────

    [Fact]
    public async Task ReleaseOciDigestClaimAsync_NoOtherClaim_ProxyOrigin_DeletesRow_ResolvesNoUploadedCandidate()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        string digest = "sha256:" + new string('1', 64);
        string blobKey = "oci/sha256/" + new string('1', 64);

        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO oci_blobs (digest, org_id, media_type, size_bytes, blob_key, origin) " +
                "VALUES (@digest, @orgId, 'application/vnd.oci.image.manifest.v1+json', 100, @blobKey, 'proxy')",
                new { digest, orgId, blobKey });
        }

        // No surviving oci_tags row, no package_versions claim — this org's row is removed, but
        // its own origin is 'proxy', so no Registry-tier physical-delete candidate is resolved
        // (proxy-tier bytes are reclaimed by cache GC; the deleter is never handed a blob).
        string? candidate = await _repo.ReleaseOciDigestClaimAsync(orgId, "library/redis", digest);
        Assert.Null(candidate);

        await using var conn2 = await _fixture.Store.OpenAsync();
        Assert.Equal(0, await conn2.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM oci_blobs WHERE digest = @digest AND org_id = @orgId", new { digest, orgId }));
    }

    [Fact]
    public async Task ReleaseOciDigestClaimAsync_UploadedOriginSoleClaim_ResolvesUploadedBlobCandidate()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        string digest = "sha256:" + new string('2', 64);
        string blobKey = "oci/sha256/" + new string('2', 64);

        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO oci_blobs (digest, org_id, media_type, size_bytes, blob_key, origin) " +
                "VALUES (@digest, @orgId, 'application/vnd.oci.image.manifest.v1+json', 100, @blobKey, 'uploaded')",
                new { digest, orgId, blobKey });
        }

        // Uploaded origin, no surviving claim — the row comes off and the blob_key is returned as
        // a Registry-tier candidate. The cross-org refcount + physical delete is the shared
        // OciOrphanBlobDeleter's job (see OciManifestDeleteRefcountTests), not this method's.
        string? candidate = await _repo.ReleaseOciDigestClaimAsync(orgId, "myorg/solo", digest);
        Assert.Equal(blobKey, candidate);

        await using var conn2 = await _fixture.Store.OpenAsync();
        Assert.Equal(0, await conn2.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM oci_blobs WHERE digest = @digest AND org_id = @orgId", new { digest, orgId }));
    }

    [Fact]
    public async Task ReleaseOciDigestClaimAsync_UploadedOrigin_RemovesOnlyThisOrgsRow_LeavesOtherOrgUntouched()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        string otherOrgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        string digest = "sha256:" + new string('3', 64);
        string blobKey = "oci/sha256/" + new string('3', 64);

        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO oci_blobs (digest, org_id, media_type, size_bytes, blob_key, origin) " +
                "VALUES (@digest, @orgId, 'application/vnd.oci.image.manifest.v1+json', 100, @blobKey, 'uploaded')",
                new { digest, orgId, blobKey });
            // Another org's row references the SAME content-addressed blob_key — the cross-org
            // sharing axis the shared deleter's refcount protects. This method is org-scoped and
            // must never touch that row; it only resolves this org's uploaded candidate.
            await conn.ExecuteAsync(
                "INSERT INTO oci_blobs (digest, org_id, media_type, size_bytes, blob_key, origin) " +
                "VALUES (@digest, @otherOrgId, 'application/vnd.oci.image.manifest.v1+json', 100, @blobKey, 'proxy')",
                new { digest, otherOrgId, blobKey });
        }

        string? candidate = await _repo.ReleaseOciDigestClaimAsync(orgId, "myorg/solo", digest);
        Assert.Equal(blobKey, candidate);

        await using var conn2 = await _fixture.Store.OpenAsync();
        Assert.Equal(0, await conn2.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM oci_blobs WHERE digest = @digest AND org_id = @orgId", new { digest, orgId }));
        Assert.Equal(1, await conn2.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM oci_blobs WHERE digest = @digest AND org_id = @otherOrgId",
            new { digest, otherOrgId }));
    }

    [Fact]
    public async Task ReleaseOciDigestClaimAsync_SurvivingTagInDifferentRepository_DoesNotDeleteRow()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        string digest = "sha256:" + new string('4', 64);
        string blobKey = "oci/sha256/" + new string('4', 64);

        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO oci_blobs (digest, org_id, media_type, size_bytes, blob_key, origin) " +
                "VALUES (@digest, @orgId, 'application/vnd.oci.image.manifest.v1+json', 100, @blobKey, 'proxy')",
                new { digest, orgId, blobKey });
            await conn.ExecuteAsync(
                "INSERT INTO oci_tags (org_id, repository, tag, digest) VALUES (@orgId, 'mirror/redis', 'latest', @digest)",
                new { orgId, digest });
        }

        // Deleting the version under a DIFFERENT repository removes only that repository's tag;
        // the surviving tag under mirror/redis blocks the oci_blobs row from being removed and
        // resolves no physical-delete candidate.
        string? candidate = await _repo.ReleaseOciDigestClaimAsync(orgId, "library/redis", digest);
        Assert.Null(candidate);

        await using var conn2 = await _fixture.Store.OpenAsync();
        Assert.Equal(1, await conn2.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM oci_blobs WHERE digest = @digest AND org_id = @orgId", new { digest, orgId }));
        Assert.Equal(1, await conn2.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM oci_tags WHERE org_id = @orgId AND repository = 'mirror/redis' AND digest = @digest",
            new { digest, orgId }));
    }

    [Fact]
    public async Task ReleaseOciDigestClaimAsync_SurvivingUploadedPackageVersionInDifferentRepository_DoesNotDeleteRow()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");
        string digest = "sha256:" + new string('5', 64);
        string blobKey = "oci/sha256/" + new string('5', 64);

        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO oci_blobs (digest, org_id, media_type, size_bytes, blob_key, origin) " +
                "VALUES (@digest, @orgId, 'application/vnd.oci.image.manifest.v1+json', 100, @blobKey, 'proxy')",
                new { digest, orgId, blobKey });
        }

        string hostedPkgId = await PackageSeeder.InsertAsync(
            _fixture.Store, orgId, "oci", "myorg/nginx", purlName: "myorg/nginx");
        await PackageSeeder.InsertVersionAsync(
            _fixture.Store, hostedPkgId, digest, Purl(digest, "nginx"), origin: "uploaded", blobKey: blobKey);

        // The hosted package_versions row under a DIFFERENT repository is a live claim even
        // though this org's oci_blobs row's own origin is 'proxy' (first-writer-wins) — the
        // claim check never inspects that column.
        string? candidate = await _repo.ReleaseOciDigestClaimAsync(orgId, "library/nginx", digest);
        Assert.Null(candidate);

        await using var conn2 = await _fixture.Store.OpenAsync();
        Assert.Equal(1, await conn2.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM oci_blobs WHERE digest = @digest AND org_id = @orgId", new { digest, orgId }));
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

    // ── RPM mixed-case name normalization ─────────────────────────────────────

    /// <summary>
    /// Regression guard for the cross-plane case-sensitivity bug. A proxy RPM whose name
    /// contains uppercase letters (e.g. 'perl-AutoLoader') was stored in cache_artifact.name
    /// with the raw NEVRA case, while packages.purl_name was always lowercased. The join
    /// <c>ca.name = p.purl_name</c> is case-sensitive in SQLite, so 'perl-AutoLoader' never
    /// matched 'perl-autoloader' and the version counted as 0 in the dashboard.
    ///
    /// The fix stores a lowercase name in cache_artifact (matching purl_name); this test seeds
    /// an uppercase-name row as the OLD code would have and verifies that VersionCount is 0
    /// (pinning the bug), then reseeds with the correct lowercase name and verifies VersionCount
    /// is 1 (pinning the fix).
    /// </summary>
    [Fact]
    public async Task ListPaginatedAsync_RpmMixedCaseProxy_VersionCountIsNonZero_WhenNameNormalized()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");

        // packages.purl_name is lowercase (as set by GetOrCreateAsync / the proxy write path).
        await PackageSeeder.InsertAsync(
            _fixture.Store, orgId, "rpm", "perl-AutoLoader",
            isProxy: true, purlName: "perl-autoloader");

        string caId = Guid.NewGuid().ToString("N");
        await using (var conn = await _fixture.Store.OpenAsync())
        {
            // OLD behaviour: name stored with raw NEVRA case — causes the join to miss.
            await conn.ExecuteAsync("""
                INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash)
                VALUES (@id, 'rpm', 'perl-AutoLoader', '5.74-513.fc42', 'perl-AutoLoader-5.74-513.fc42.noarch.rpm', 'proxy/abcd1234', 'abcd1234')
                """, new { id = caId });
            await conn.ExecuteAsync(
                "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES (@orgId, @caId)",
                new { orgId, caId });
        }

        // With the OLD code (raw-case name in cache_artifact), VersionCount would be 0
        // because 'perl-AutoLoader' <> 'perl-autoloader' in SQLite.
        var (itemsBefore, _) = await _repo.ListPaginatedAsync(
            new PackageListQuery(orgId, Limit: 10, Offset: 0, Ecosystem: "rpm"));
        Assert.Equal(0, Assert.Single(itemsBefore).VersionCount);

        // Simulate what the migration does: normalize the name to lowercase.
        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE cache_artifact SET name = lower(name) WHERE ecosystem = 'rpm' AND name <> lower(name)");
        }

        // After normalization (matching the fixed write path), VersionCount must be 1.
        var (itemsAfter, _) = await _repo.ListPaginatedAsync(
            new PackageListQuery(orgId, Limit: 10, Offset: 0, Ecosystem: "rpm"));
        Assert.Equal(1, Assert.Single(itemsAfter).VersionCount);
    }

    /// <summary>
    /// Verifies that a freshly proxied mixed-case RPM (as written by the fixed code path)
    /// registers a non-zero VersionCount immediately — no migration needed for new fetches.
    /// </summary>
    [Fact]
    public async Task ListPaginatedAsync_RpmMixedCaseProxy_NewFetch_VersionCountIsOne()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"org-{Guid.NewGuid():N}");

        // packages.purl_name is lowercase — mirrors GetOrCreateAsync behavior.
        await PackageSeeder.InsertAsync(
            _fixture.Store, orgId, "rpm", "perl-Carp",
            isProxy: true, purlName: "perl-carp");

        // Fixed write path: cache_artifact.name is also lowercased.
        string caId = Guid.NewGuid().ToString("N");
        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync("""
                INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash)
                VALUES (@id, 'rpm', 'perl-carp', '1.50-511.fc42', 'perl-Carp-1.50-511.fc42.noarch.rpm', 'proxy/ef012345', 'ef012345')
                """, new { id = caId });
            await conn.ExecuteAsync(
                "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES (@orgId, @caId)",
                new { orgId, caId });
        }

        var (items, _) = await _repo.ListPaginatedAsync(
            new PackageListQuery(orgId, Limit: 10, Offset: 0, Ecosystem: "rpm"));
        Assert.Equal(1, Assert.Single(items).VersionCount);
    }
}
