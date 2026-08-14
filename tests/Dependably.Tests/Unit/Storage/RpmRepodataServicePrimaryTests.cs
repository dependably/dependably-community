using System.Xml.Linq;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit.Storage;

/// <summary>
/// Regression coverage for <see cref="RpmRepodataService.BuildPrimaryAsync"/> against the
/// real SQLite-backed store. SQLite reports <c>INTEGER</c> as <see cref="long"/>, and
/// Dapper's positional-record binder won't narrow Int64 → Int32 — so prior to the
/// RpmPrimaryRow widening, this method threw on every call (even when the join returned
/// zero rows, because Dapper builds the deserializer at query-prepare time).
/// </summary>
[Trait("Category", "Unit")]
public sealed class RpmRepodataServicePrimaryTests : IClassFixture<InMemoryDbFixture>
{
    private readonly InMemoryDbFixture _fixture;

    public RpmRepodataServicePrimaryTests(InMemoryDbFixture fixture) => _fixture = fixture;

    [Fact]
    public async Task BuildPrimaryAsync_NoRows_ReturnsEmptyMetadataDocument()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        var svc = new RpmRepodataService(_fixture.Store, NullLogger<RpmRepodataService>.Instance, TimeProvider.System);

        string xml = await svc.BuildPrimaryAsync(orgId, CancellationToken.None);

        var doc = XDocument.Parse(xml);
        XNamespace common = "http://linux.duke.edu/metadata/common";
        Assert.Equal("metadata", doc.Root!.Name.LocalName);
        Assert.Equal(common.NamespaceName, doc.Root.Name.NamespaceName);
        Assert.Equal("0", doc.Root.Attribute("packages")!.Value);
        Assert.Empty(doc.Root.Elements(common + "package"));
    }

    [Fact]
    public async Task BuildPrimaryAsync_WithRow_RendersPackageWithIntegerFields()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        string pkgId = await PackageSeeder.InsertAsync(
            _fixture.Store, orgId, "rpm", "hello",
            purlName: "hello");
        string pvId = await PackageSeeder.InsertVersionAsync(
            _fixture.Store, pkgId,
            version: "2.10-1.el9",
            purl: "pkg:rpm/hello@2.10-1.el9?arch=x86_64",
            blobKey: "rpm/registry/hello-2.10-1.el9.x86_64.rpm",
            sizeBytes: 12345,
            checksumSha256: new string('a', 64));

        await InsertRpmMetadataAsync(pvId);

        var svc = new RpmRepodataService(_fixture.Store, NullLogger<RpmRepodataService>.Instance, TimeProvider.System);

        string xml = await svc.BuildPrimaryAsync(orgId, CancellationToken.None);

        XNamespace common = "http://linux.duke.edu/metadata/common";
        XNamespace rpm = "http://linux.duke.edu/metadata/rpm";
        var doc = XDocument.Parse(xml);
        Assert.Equal("1", doc.Root!.Attribute("packages")!.Value);

        var pkg = Assert.Single(doc.Root.Elements(common + "package"));
        Assert.Equal("hello", pkg.Element(common + "name")!.Value);
        Assert.Equal("x86_64", pkg.Element(common + "arch")!.Value);

        var version = pkg.Element(common + "version")!;
        Assert.Equal("0", version.Attribute("epoch")!.Value);
        Assert.Equal("2.10", version.Attribute("ver")!.Value);
        Assert.Equal("1.el9", version.Attribute("rel")!.Value);

        var headerRange = pkg.Element(common + "format")!.Element(rpm + "header-range")!;
        Assert.Equal("440", headerRange.Attribute("start")!.Value);
        Assert.Equal("2048", headerRange.Attribute("end")!.Value);

        var size = pkg.Element(common + "size")!;
        Assert.Equal("12345", size.Attribute("package")!.Value);
        Assert.Equal("65536", size.Attribute("installed")!.Value);
        Assert.Equal("60000", size.Attribute("archive")!.Value);

        Assert.Equal(
            "packages/hello-2.10-1.el9.x86_64.rpm",
            pkg.Element(common + "location")!.Attribute("href")!.Value);
    }

    [Fact]
    public async Task BuildPrimaryAsync_FiltersByTenant()
    {
        string orgA = await OrgSeeder.InsertAsync(_fixture.Store, $"a-{Guid.NewGuid():N}");
        string orgB = await OrgSeeder.InsertAsync(_fixture.Store, $"b-{Guid.NewGuid():N}");

        string pkgB = await PackageSeeder.InsertAsync(_fixture.Store, orgB, "rpm", "from-b", purlName: "from-b");
        string pvB = await PackageSeeder.InsertVersionAsync(
            _fixture.Store, pkgB,
            version: "1.0-1.el9",
            purl: "pkg:rpm/from-b@1.0-1.el9?arch=noarch",
            blobKey: "rpm/registry/from-b-1.0-1.el9.noarch.rpm");
        await InsertRpmMetadataAsync(pvB, name: "from-b", arch: "noarch");

        var svc = new RpmRepodataService(_fixture.Store, NullLogger<RpmRepodataService>.Instance, TimeProvider.System);

        string xmlA = await svc.BuildPrimaryAsync(orgA, CancellationToken.None);
        var docA = XDocument.Parse(xmlA);
        Assert.Equal("0", docA.Root!.Attribute("packages")!.Value);

        string xmlB = await svc.BuildPrimaryAsync(orgB, CancellationToken.None);
        var docB = XDocument.Parse(xmlB);
        Assert.Equal("1", docB.Root!.Attribute("packages")!.Value);
    }

    /// <summary>
    /// A tenant whose own upstream served a different <c>.rpm</c> than the shared
    /// <c>cache_artifact</c> row's must see its own checksum in <c>primary.xml</c>'s
    /// <c>&lt;checksum pkgid="YES"&gt;</c> — never the shared row's, which would describe another
    /// tenant's package bytes. Pins that <see cref="RpmRepodataService.LoadLocalRowsAsync"/>'s
    /// proxy-plane arm resolves <c>Sha256</c> through <c>COALESCE(taa.content_hash,
    /// ca.content_hash)</c> rather than reading the shared row directly.
    /// </summary>
    [Fact]
    public async Task BuildPrimaryAsync_ForADivergingProxyTenant_RendersTheTenantsOwnChecksum()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        const string sharedHash = "1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa";
        const string ownHash = "2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb";

        var cacheArtifacts = new CacheArtifactRepository(_fixture.Store);
        var cacheArtifact = new CacheArtifact
        {
            Id = Guid.NewGuid().ToString("D"),
            Ecosystem = "rpm",
            Name = "curl",
            Version = "8.0-1.el9",
            Filename = "curl-8.0-1.el9.x86_64.rpm",
            BlobKey = $"proxy/{sharedHash}/curl-8.0-1.el9.x86_64.rpm",
            ContentHash = sharedHash,
            SizeBytes = 500,
            FirstCachedAt = TestTime.KnownNow,
            LastAccessedAt = TestTime.KnownNow,
        };
        await cacheArtifacts.InsertAsync(cacheArtifact);

        await new TenantArtifactAccessRepository(_fixture.Store).UpsertAsync(
            orgId, cacheArtifact.Id, TestTime.KnownNow,
            new TenantContentBinding(ownHash, $"proxy/{ownHash}/curl-8.0-1.el9.x86_64.rpm", 500));

        await using (var conn = await _fixture.Store.OpenAsync())
        {
            await conn.ExecuteAsync("""
                INSERT INTO rpm_metadata
                    (id, cache_artifact_id, owner_kind,
                     rpm_name, epoch, rpm_version, rpm_release, arch,
                     summary, description, rpm_license)
                VALUES
                    (lower(hex(randomblob(16))), @caId, 'cache_artifact',
                     'curl', 0, '8.0', '1.el9', 'x86_64',
                     'A tool for transferring data', 'curl is a tool for transferring data.',
                     'MIT')
                """,
                new { caId = cacheArtifact.Id });
        }

        var svc = new RpmRepodataService(_fixture.Store, NullLogger<RpmRepodataService>.Instance, TimeProvider.System);

        string xml = await svc.BuildPrimaryAsync(orgId, CancellationToken.None);

        XNamespace common = "http://linux.duke.edu/metadata/common";
        var doc = XDocument.Parse(xml);
        var pkg = Assert.Single(doc.Root!.Elements(common + "package"));
        string checksum = pkg.Element(common + "checksum")!.Value;
        Assert.Equal(ownHash, checksum);
        Assert.NotEqual(sharedHash, checksum);
    }

    private async Task InsertRpmMetadataAsync(
        string packageVersionId,
        string name = "hello",
        string arch = "x86_64")
    {
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync("""
            INSERT INTO rpm_metadata
                (id, package_version_id, owner_kind,
                 rpm_name, epoch, rpm_version, rpm_release, arch,
                 summary, description, build_host, build_time,
                 installed_size, archive_size, header_start, header_end,
                 rpm_license)
            VALUES
                (lower(hex(randomblob(16))), @pvId, 'package_version',
                 @name, 0, '2.10', '1.el9', @arch,
                 'A GNU greeting program', 'The GNU Hello program produces a familiar, friendly greeting.',
                 'builder.example.com', 1716393600,
                 65536, 60000, 440, 2048,
                 'GPL-3.0-or-later')
            """,
            new { pvId = packageVersionId, name, arch });
    }
}
