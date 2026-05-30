using System.Xml.Linq;
using Dapper;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Xunit;

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
        var orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        var svc = new RpmRepodataService(_fixture.Store);

        var xml = await svc.BuildPrimaryAsync(orgId, CancellationToken.None);

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
        var orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        var pkgId = await PackageSeeder.InsertAsync(
            _fixture.Store, orgId, "rpm", "hello",
            purlName: "hello");
        var pvId = await PackageSeeder.InsertVersionAsync(
            _fixture.Store, pkgId,
            version: "2.10-1.el9",
            purl: "pkg:rpm/hello@2.10-1.el9?arch=x86_64",
            blobKey: "rpm/registry/hello-2.10-1.el9.x86_64.rpm",
            sizeBytes: 12345,
            checksumSha256: new string('a', 64));

        await InsertRpmMetadataAsync(pvId);

        var svc = new RpmRepodataService(_fixture.Store);

        var xml = await svc.BuildPrimaryAsync(orgId, CancellationToken.None);

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
        var orgA = await OrgSeeder.InsertAsync(_fixture.Store, $"a-{Guid.NewGuid():N}");
        var orgB = await OrgSeeder.InsertAsync(_fixture.Store, $"b-{Guid.NewGuid():N}");

        var pkgB = await PackageSeeder.InsertAsync(_fixture.Store, orgB, "rpm", "from-b", purlName: "from-b");
        var pvB = await PackageSeeder.InsertVersionAsync(
            _fixture.Store, pkgB,
            version: "1.0-1.el9",
            purl: "pkg:rpm/from-b@1.0-1.el9?arch=noarch",
            blobKey: "rpm/registry/from-b-1.0-1.el9.noarch.rpm");
        await InsertRpmMetadataAsync(pvB, name: "from-b", arch: "noarch");

        var svc = new RpmRepodataService(_fixture.Store);

        var xmlA = await svc.BuildPrimaryAsync(orgA, CancellationToken.None);
        var docA = XDocument.Parse(xmlA);
        Assert.Equal("0", docA.Root!.Attribute("packages")!.Value);

        var xmlB = await svc.BuildPrimaryAsync(orgB, CancellationToken.None);
        var docB = XDocument.Parse(xmlB);
        Assert.Equal("1", docB.Root!.Attribute("packages")!.Value);
    }

    private async Task InsertRpmMetadataAsync(
        string packageVersionId,
        string name = "hello",
        string arch = "x86_64")
    {
        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync("""
            INSERT INTO rpm_metadata
                (package_version_id, rpm_name, epoch, rpm_version, rpm_release, arch,
                 summary, description, build_host, build_time,
                 installed_size, archive_size, header_start, header_end,
                 rpm_license)
            VALUES
                (@pvId, @name, 0, '2.10', '1.el9', @arch,
                 'A GNU greeting program', 'The GNU Hello program produces a familiar, friendly greeting.',
                 'builder.example.com', 1716393600,
                 65536, 60000, 440, 2048,
                 'GPL-3.0-or-later')
            """,
            new { pvId = packageVersionId, name, arch });
    }
}
