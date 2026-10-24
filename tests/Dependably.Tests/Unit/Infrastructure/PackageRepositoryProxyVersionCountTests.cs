using Dapper;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// The Packages tile's VersionCount counts VERSIONS, on both planes.
///
/// cache_artifact is keyed UNIQUE (ecosystem, name, version, filename), so one proxied version owns
/// one row per file — a Maven version spans jar+pom+sources+javadoc, NuGet adds a .nuspec, PyPI a
/// wheel beside the sdist. Counting rows reports a file tally as a version count, and a version
/// cached on the proxy plane and pushed on the uploaded plane casts a row on each. Both collapse
/// through UNION + COUNT(DISTINCT), so the tile reports what the detail page renders.
/// </summary>
[Trait("Category", "Unit")]
public sealed class PackageRepositoryProxyVersionCountTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly TimeProvider _clock = TestTime.Frozen();
    private string _orgId = "";

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        _orgId = await OrgSeeder.InsertAsync(_db, "acme");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    // A packages row for the tile to aggregate over. purl_name is the key the proxy arm joins on.
    private async Task<string> SeedPackageAsync(string ecosystem, string name)
    {
        string pkgId = Guid.NewGuid().ToString("N");
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy, created_at)
            VALUES (@pkgId, @orgId, @ecosystem, @name, @name, 1, '2026-06-01T00:00:00Z')
            """,
            new { pkgId, orgId = _orgId, ecosystem, name });
        return pkgId;
    }

    // One proxied FILE of a version: its own cache_artifact row plus this org's access row.
    private async Task SeedProxyFileAsync(
        string ecosystem, string name, string version, string filename, long downloads = 0)
    {
        var repo = new CacheArtifactRepository(_db);
        var inserted = await repo.InsertAsync(new CacheArtifact
        {
            Id = Guid.NewGuid().ToString("D"),
            Ecosystem = ecosystem,
            Name = name,
            Version = version,
            Filename = filename,
            BlobKey = Dependably.Storage.BlobKeys.Proxy(Convert.ToHexString(
                System.Security.Cryptography.SHA256.HashData(
                    System.Text.Encoding.UTF8.GetBytes(name + version + filename))).ToLowerInvariant()),
            ContentHash = "abc123",
            SizeBytes = 10,
        });

        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO tenant_artifact_access (org_id, cache_artifact_id, download_count)
            VALUES (@orgId, @id, @downloads)
            """,
            new { orgId = _orgId, id = inserted.Id, downloads });
    }

    private async Task SeedUploadedVersionAsync(string pkgId, string version, long downloads = 0)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO package_versions
                (id, package_id, version, purl, blob_key, filename, size_bytes, download_count, origin)
            VALUES (@id, @pkgId, @version, @purl, @blobKey, @filename, 10, @downloads, 'uploaded')
            """,
            new
            {
                id = Guid.NewGuid().ToString("N"),
                pkgId,
                version,
                purl = $"pkg:generic/{Guid.NewGuid():N}@{version}",
                blobKey = $"store/{Guid.NewGuid():N}",
                filename = $"f-{version}.bin",
                downloads,
            });
    }

    private async Task<Package> TileRowAsync(string ecosystem)
    {
        var repo = new PackageRepository(_db);
        var (items, _) = await repo.ListPaginatedAsync(
            new PackageListQuery(_orgId, Limit: 50, Offset: 0, Ecosystem: ecosystem));
        return Assert.Single(items);
    }

    // The number of distinct versions the package-detail page renders — the merge of both planes
    // that the tile must agree with.
    private async Task<int> DetailPageDistinctVersionsAsync(string pkgId, string ecosystem, string name)
    {
        var packages = new PackageRepository(_db);
        var inventory = new ArtifactInventoryRepository(
            _db, packages, new CacheArtifactRepository(_db),
            new VulnerabilityRepository(_db, _clock));
        var versions = await inventory.ListServeableVersionsAsync(_orgId, pkgId, ecosystem, name);
        // The page groups rows by the exact version string (VersionTable.svelte buildGroups), after
        // the management endpoint's NuGet sidecar collapse.
        return ArtifactInventoryRepository.CollapseSidecarProxyRows(ecosystem, versions)
            .Select(v => v.Version).Distinct(StringComparer.Ordinal).Count();
    }

    [Fact]
    public async Task ProxiedMavenVersion_WithFourFiles_CountsAsOneVersion()
    {
        string pkgId = await SeedPackageAsync("maven", "com.acme:widget");

        // One version, four files — exactly what a Maven resolve caches.
        await SeedProxyFileAsync("maven", "com.acme:widget", "1.0.0", "widget-1.0.0.jar");
        await SeedProxyFileAsync("maven", "com.acme:widget", "1.0.0", "widget-1.0.0.pom");
        await SeedProxyFileAsync("maven", "com.acme:widget", "1.0.0", "widget-1.0.0-sources.jar");
        await SeedProxyFileAsync("maven", "com.acme:widget", "1.0.0", "widget-1.0.0-javadoc.jar");

        var row = await TileRowAsync("maven");

        Assert.Equal(1, row.VersionCount);
        Assert.Equal(await DetailPageDistinctVersionsAsync(pkgId, "maven", "com.acme:widget"), row.VersionCount);
    }

    [Fact]
    public async Task ProxiedNuGetVersion_WithNuspecSidecar_CountsAsOneVersion()
    {
        string pkgId = await SeedPackageAsync("nuget", "newtonsoft.json");

        await SeedProxyFileAsync("nuget", "newtonsoft.json", "13.0.3", "newtonsoft.json.13.0.3.nupkg");
        await SeedProxyFileAsync("nuget", "newtonsoft.json", "13.0.3", "newtonsoft.json.nuspec");

        var row = await TileRowAsync("nuget");

        Assert.Equal(1, row.VersionCount);
        Assert.Equal(await DetailPageDistinctVersionsAsync(pkgId, "nuget", "newtonsoft.json"), row.VersionCount);
    }

    [Fact]
    public async Task UploadedPyPiVersions_Pep440Equal_CountOnce_AndDistinctOnesCountSeparately()
    {
        string pkgId = await SeedPackageAsync("pypi", "dupes");
        await SeedUploadedVersionAsync(pkgId, "1.0.0rc1");
        await SeedUploadedVersionAsync(pkgId, "1.0.0-rc1");

        Assert.Equal(1, (await TileRowAsync("pypi")).VersionCount);

        await SeedUploadedVersionAsync(pkgId, "1.0.0rc2");

        Assert.Equal(2, (await TileRowAsync("pypi")).VersionCount);
    }

    [Fact]
    public async Task ProxiedPyPiVersion_WithSdistAndWheel_CountsAsOneVersion()
    {
        string pkgId = await SeedPackageAsync("pypi", "requests");

        await SeedProxyFileAsync("pypi", "requests", "2.31.0", "requests-2.31.0.tar.gz");
        await SeedProxyFileAsync("pypi", "requests", "2.31.0", "requests-2.31.0-py3-none-any.whl");

        var row = await TileRowAsync("pypi");

        Assert.Equal(1, row.VersionCount);
        Assert.Equal(await DetailPageDistinctVersionsAsync(pkgId, "pypi", "requests"), row.VersionCount);
    }

    [Fact]
    public async Task VersionOnBothPlanes_CountsOnce()
    {
        string pkgId = await SeedPackageAsync("npm", "left-pad");

        // The org pushed a private override of a version it also proxies: one version, two planes.
        await SeedUploadedVersionAsync(pkgId, "1.0.0");
        await SeedProxyFileAsync("npm", "left-pad", "1.0.0", "left-pad-1.0.0.tgz");

        var row = await TileRowAsync("npm");

        Assert.Equal(1, row.VersionCount);
        // The detail page suppresses the proxied copy of an uploaded version; the tile must agree.
        Assert.Equal(await DetailPageDistinctVersionsAsync(pkgId, "npm", "left-pad"), row.VersionCount);
    }

    [Fact]
    public async Task MixedPlanes_MultiFileAndOverlap_CountsDistinctVersionsAndAgreesWithDetailPage()
    {
        string pkgId = await SeedPackageAsync("maven", "com.acme:mixed");

        // 1.0.0 — uploaded only.
        await SeedUploadedVersionAsync(pkgId, "1.0.0");
        // 2.0.0 — on BOTH planes (uploaded override of a proxied version), proxied as 2 files.
        await SeedUploadedVersionAsync(pkgId, "2.0.0");
        await SeedProxyFileAsync("maven", "com.acme:mixed", "2.0.0", "mixed-2.0.0.jar");
        await SeedProxyFileAsync("maven", "com.acme:mixed", "2.0.0", "mixed-2.0.0.pom");
        // 3.0.0 — proxy only, 3 files.
        await SeedProxyFileAsync("maven", "com.acme:mixed", "3.0.0", "mixed-3.0.0.jar");
        await SeedProxyFileAsync("maven", "com.acme:mixed", "3.0.0", "mixed-3.0.0.pom");
        await SeedProxyFileAsync("maven", "com.acme:mixed", "3.0.0", "mixed-3.0.0-sources.jar");

        var row = await TileRowAsync("maven");

        // Three distinct versions across 2 uploaded rows + 5 cache_artifact rows.
        Assert.Equal(3, row.VersionCount);
        Assert.Equal(await DetailPageDistinctVersionsAsync(pkgId, "maven", "com.acme:mixed"), row.VersionCount);
    }

    // An uploaded version and a proxied version differing only in case. Where the ecosystem's
    // version identity is case-sensitive they are two real versions and both are listed and
    // counted; where it folds case (NuGet, PyPI) the proxied copy is shadowed. The tile and the
    // detail list must agree either way.
    [Theory]
    [InlineData("npm", "case-npm", 2)]
    [InlineData("golang", "example.com/case-go", 2)]
    [InlineData("cargo", "case-cargo", 2)]
    [InlineData("maven", "com.acme:case-mvn", 2)]
    [InlineData("hex", "case_hex", 2)]
    [InlineData("nuget", "case.nuget", 1)]
    [InlineData("pypi", "case-pypi", 1)]
    public async Task CaseOnlyDifferentVersionOnBothPlanes_ShadowsOnlyWhereVersionIdentityFoldsCase(
        string ecosystem, string name, int expected)
    {
        string pkgId = await SeedPackageAsync(ecosystem, name);

        await SeedUploadedVersionAsync(pkgId, "1.0.0-RC1");
        await SeedProxyFileAsync(ecosystem, name, "1.0.0-rc1", "case-1.0.0-rc1.bin");

        var row = await TileRowAsync(ecosystem);

        Assert.Equal(expected, row.VersionCount);
        Assert.Equal(expected, await DetailPageDistinctVersionsAsync(pkgId, ecosystem, name));
    }

    // PEP 440 spells one release many ways. An uploaded and a proxied spelling of the same release
    // shadow each other, count once, and the tile agrees with the detail list.
    [Theory]
    [InlineData("1.0.0-rc1", "1.0.0rc1")]
    [InlineData("1.0.0rc1", "1.0.0.rc1")]
    [InlineData("v1.0", "1.0")]
    [InlineData("1.0alpha1", "1.0a1")]
    [InlineData("1.0-post1", "1.0.post1")]
    [InlineData("1.0.post", "1.0.post0")]
    public async Task PyPiSpellingVariantsOnBothPlanes_ShadowAndCountOnce(string uploaded, string proxied)
    {
        string pkgId = await SeedPackageAsync("pypi", "spell");

        await SeedUploadedVersionAsync(pkgId, uploaded);
        await SeedProxyFileAsync("pypi", "spell", proxied, "spell-" + proxied + ".tar.gz");

        var row = await TileRowAsync("pypi");

        Assert.Equal(1, row.VersionCount);
        Assert.Equal(1, await DetailPageDistinctVersionsAsync(pkgId, "pypi", "spell"));
        var inventory = new ArtifactInventoryRepository(
            _db, new PackageRepository(_db), new CacheArtifactRepository(_db), new VulnerabilityRepository(_db, _clock));
        var listed = await inventory.ListServeableVersionsAsync(_orgId, pkgId, "pypi", "spell");
        Assert.Equal(uploaded, Assert.Single(listed).Version);
    }

    // Within one plane the page lists versions by exact string, so two spellings of a release
    // there are two rows and count as two; only the cross-plane shadow follows the canonical form.
    [Fact]
    public async Task PyPiProxyFilesOfOneReleaseInTwoSpellings_CountAsTheRowsListed()
    {
        string pkgId = await SeedPackageAsync("pypi", "proxyspell");

        await SeedProxyFileAsync("pypi", "proxyspell", "1.0RC1", "proxyspell-1.0RC1.tar.gz");
        await SeedProxyFileAsync("pypi", "proxyspell", "1.0rc1", "proxyspell-1.0rc1-py3-none-any.whl");

        var row = await TileRowAsync("pypi");

        Assert.Equal(2, row.VersionCount);
        Assert.Equal(2, await DetailPageDistinctVersionsAsync(pkgId, "pypi", "proxyspell"));
    }

    // A respelled publish attaches to the stored row, so this shape only exists for rows stored
    // before that resolution. The tile counts the release once; the page still lists each stored
    // row so an operator can see and delete the stray spelling.
    [Fact]
    public async Task PyPiUploadedSpellingsOfOneRelease_CountOnce_WhileBothRowsStayListed()
    {
        string pkgId = await SeedPackageAsync("pypi", "upspell");

        await SeedUploadedVersionAsync(pkgId, "1.0.0-rc1");
        await SeedUploadedVersionAsync(pkgId, "1.0.0rc1");
        await SeedProxyFileAsync("pypi", "upspell", "1.0.0.rc1", "upspell-1.0.0.rc1.tar.gz");

        var row = await TileRowAsync("pypi");

        Assert.Equal(1, row.VersionCount);
        Assert.Equal(2, await DetailPageDistinctVersionsAsync(pkgId, "pypi", "upspell"));
    }

    [Fact]
    public async Task PyPiDistinctReleases_StayDistinct()
    {
        string pkgId = await SeedPackageAsync("pypi", "distinct");

        await SeedUploadedVersionAsync(pkgId, "1.0rc1");
        await SeedProxyFileAsync("pypi", "distinct", "1.0rc2", "distinct-1.0rc2.tar.gz");

        var row = await TileRowAsync("pypi");

        Assert.Equal(2, row.VersionCount);
        Assert.Equal(2, await DetailPageDistinctVersionsAsync(pkgId, "pypi", "distinct"));
    }

    [Fact]
    public async Task PyPiCount_IsScopedToTheOrgsOwnCacheAccess()
    {
        string pkgId = await SeedPackageAsync("pypi", "scoped");
        await SeedUploadedVersionAsync(pkgId, "1.0");

        string otherOrg = await OrgSeeder.InsertAsync(_db, "other");
        var inserted = await new CacheArtifactRepository(_db).InsertAsync(new CacheArtifact
        {
            Id = Guid.NewGuid().ToString("D"),
            Ecosystem = "pypi",
            Name = "scoped",
            Version = "2.0",
            Filename = "scoped-2.0.tar.gz",
            BlobKey = Dependably.Storage.BlobKeys.Proxy(new string('a', 64)),
            ContentHash = "abc123",
            SizeBytes = 10,
        });
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id, download_count) VALUES (@otherOrg, @id, 0)",
                new { otherOrg, id = inserted.Id });
        }

        var row = await TileRowAsync("pypi");

        Assert.Equal(1, row.VersionCount);
    }

    [Fact]
    public async Task NuGetProxyFiles_DifferingOnlyInCase_CountAsOneVersion()
    {
        string pkgId = await SeedPackageAsync("nuget", "cased.pkg");

        await SeedProxyFileAsync("nuget", "cased.pkg", "1.0.0-RC1", "cased.pkg.1.0.0-RC1.nupkg");
        await SeedProxyFileAsync("nuget", "cased.pkg", "1.0.0-rc1", "cased.pkg.1.0.0-rc1.nuspec");

        var row = await TileRowAsync("nuget");

        Assert.Equal(1, row.VersionCount);
        Assert.Equal(await DetailPageDistinctVersionsAsync(pkgId, "nuget", "cased.pkg"), row.VersionCount);
    }

    [Theory]
    [InlineData("npm", "case-npm")]
    [InlineData("maven", "com.acme:case-mvn")]
    public async Task ProxyOnly_CaseOnlyVariants_StayTwoVersions_AsTheListShowsThem(string ecosystem, string name)
    {
        string pkgId = await SeedPackageAsync(ecosystem, name);

        await SeedProxyFileAsync(ecosystem, name, "1.0.0-RC1", "a-1.0.0-RC1.bin");
        await SeedProxyFileAsync(ecosystem, name, "1.0.0-rc1", "a-1.0.0-rc1.bin");

        var row = await TileRowAsync(ecosystem);

        Assert.Equal(2, row.VersionCount);
        Assert.Equal(2, await DetailPageDistinctVersionsAsync(pkgId, ecosystem, name));
    }

    [Theory]
    [InlineData("npm", "up-npm")]
    [InlineData("maven", "com.acme:up-mvn")]
    public async Task UploadedOnly_CaseOnlyVariants_StayTwoVersions_AsTheListShowsThem(string ecosystem, string name)
    {
        string pkgId = await SeedPackageAsync(ecosystem, name);

        await SeedUploadedVersionAsync(pkgId, "1.0.0-RC1");
        await SeedUploadedVersionAsync(pkgId, "1.0.0-rc1");

        var row = await TileRowAsync(ecosystem);

        Assert.Equal(2, row.VersionCount);
        Assert.Equal(2, await DetailPageDistinctVersionsAsync(pkgId, ecosystem, name));
    }

    [Fact]
    public async Task TotalDownloads_SumsEveryFileFetch_OnBothPlanes()
    {
        string pkgId = await SeedPackageAsync("maven", "com.acme:dl");

        // Downloads are counted per file fetched, on both planes: the cache plane bumps
        // download_count per (org_id, cache_artifact_id), the uploaded plane per version row. Each
        // counter is an independent tally of real fetches, so the tile sums them rather than
        // deduping per version the way VersionCount does.
        await SeedUploadedVersionAsync(pkgId, "1.0.0", downloads: 5);
        await SeedProxyFileAsync("maven", "com.acme:dl", "2.0.0", "dl-2.0.0.jar", downloads: 3);
        await SeedProxyFileAsync("maven", "com.acme:dl", "2.0.0", "dl-2.0.0.pom", downloads: 2);

        var row = await TileRowAsync("maven");

        Assert.Equal(10, row.TotalDownloads);
        // Versions still collapse, even though their download tallies do not.
        Assert.Equal(2, row.VersionCount);
    }
}
