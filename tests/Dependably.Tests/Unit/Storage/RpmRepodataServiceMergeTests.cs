using System.IO.Compression;
using System.Xml.Linq;
using Dapper;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Dependably.Tests.Unit.Storage;

/// <summary>
/// Coverage for <see cref="RpmRepodataService.BuildMergedPrimaryGzAsync"/> — the union of locally
/// published RPMs with the upstream repo's packages that backs <c>Rpm:UpstreamMode=merged</c>.
/// Local versions must shadow upstream on filename (NEVRA) collision, and every upstream
/// <c>&lt;location&gt;</c> must be rewritten to the flat <c>packages/{file}</c> route so dnf
/// downloads through Dependably rather than the mirror.
/// </summary>
[Trait("Category", "Unit")]
public sealed class RpmRepodataServiceMergeTests : IClassFixture<InMemoryDbFixture>
{
    private static readonly XNamespace Common = "http://linux.duke.edu/metadata/common";
    private static readonly XNamespace Rpm = "http://linux.duke.edu/metadata/rpm";

    private readonly InMemoryDbFixture _fixture;

    public RpmRepodataServiceMergeTests(InMemoryDbFixture fixture) => _fixture = fixture;

    [Fact]
    public async Task BuildMergedPrimaryAsync_UnionsLocalAndUpstream_LocalShadowsOnFilenameCollision()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        await SeedLocalHelloAsync(orgId);

        // Upstream advertises the same hello NEVRA (must be shadowed by the local copy) plus a
        // unique `tree` package (must survive, with its href rewritten to the flat route).
        byte[] upstreamGz = BuildUpstreamPrimaryGz(
            ("hello", "2.10", "1.el9", "x86_64", "Packages/h/hello-2.10-1.el9.x86_64.rpm", 1),
            ("tree", "2.1.1", "1.el9", "x86_64", "Packages/t/tree-2.1.1-1.el9.x86_64.rpm", 4242));

        var svc = new RpmRepodataService(_fixture.Store, NullLogger<RpmRepodataService>.Instance, TimeProvider.System);
        byte[] gz = await svc.BuildMergedPrimaryGzAsync(orgId, upstreamGz, CancellationToken.None);
        string xml = System.Text.Encoding.UTF8.GetString(Gunzip(gz));
        var doc = XDocument.Parse(xml);

        var packages = doc.Root!.Elements(Common + "package").ToList();
        Assert.Equal("2", doc.Root.Attribute("packages")!.Value);
        Assert.Equal(2, packages.Count);

        // hello appears exactly once — the local copy (flat href), not the shadowed upstream one.
        var hello = Assert.Single(packages, p => p.Element(Common + "name")!.Value == "hello");
        Assert.Equal("packages/hello-2.10-1.el9.x86_64.rpm",
            hello.Element(Common + "location")!.Attribute("href")!.Value);

        // tree comes from upstream — href rewritten to the flat route, size preserved verbatim.
        var tree = Assert.Single(packages, p => p.Element(Common + "name")!.Value == "tree");
        Assert.Equal("packages/tree-2.1.1-1.el9.x86_64.rpm",
            tree.Element(Common + "location")!.Attribute("href")!.Value);
        Assert.Equal("4242", tree.Element(Common + "size")!.Attribute("package")!.Value);
    }

    [Fact]
    public async Task BuildMergedPrimaryAsync_NoLocalPackages_ServesUpstreamRewritten()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        byte[] upstreamGz = BuildUpstreamPrimaryGz(
            ("tree", "2.1.1", "1.el9", "x86_64", "Packages/t/tree-2.1.1-1.el9.x86_64.rpm", 7));

        var svc = new RpmRepodataService(_fixture.Store, NullLogger<RpmRepodataService>.Instance, TimeProvider.System);
        byte[] gz = await svc.BuildMergedPrimaryGzAsync(orgId, upstreamGz, CancellationToken.None);
        string xml = System.Text.Encoding.UTF8.GetString(Gunzip(gz));
        var doc = XDocument.Parse(xml);

        var pkg = Assert.Single(doc.Root!.Elements(Common + "package"));
        Assert.Equal("tree", pkg.Element(Common + "name")!.Value);
        Assert.Equal("packages/tree-2.1.1-1.el9.x86_64.rpm",
            pkg.Element(Common + "location")!.Attribute("href")!.Value);
    }

    [Fact]
    public async Task BuildMergedPrimaryGzAsync_StripsXmlBase_AndPreservesUpstreamFieldsVerbatim()
    {
        // Pins the streaming rewrite in BuildMergedPrimaryGzAsync/ExtractUpstreamPackages: every
        // entry here comes from upstream (no local packages), exercising the detach-and-mutate
        // path (each element is removed from the source doc and reused directly) for every
        // package. An xml:base attribute (as real mirrors sometimes emit) must be stripped, the
        // href must be rewritten to the flat route, and every other field must survive byte-for-byte.
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        byte[] upstreamGz = BuildUpstreamPrimaryGzWithXmlBase(
            ("curl", "8.6.0", "1.fc40", "x86_64", "Packages/c/curl-8.6.0-1.fc40.x86_64.rpm",
             "HTTP client library", "A command line tool for transferring data.", "MIT"),
            ("wget", "1.21", "3.fc40", "x86_64", "Packages/w/wget-1.21-3.fc40.x86_64.rpm",
             "A utility for retrieving files", "GNU Wget retrieves content from web servers.", "GPL-3.0-or-later"));

        var svc = new RpmRepodataService(_fixture.Store, NullLogger<RpmRepodataService>.Instance, TimeProvider.System);
        byte[] gz = await svc.BuildMergedPrimaryGzAsync(orgId, upstreamGz, CancellationToken.None);
        string xml = System.Text.Encoding.UTF8.GetString(Gunzip(gz));
        var doc = XDocument.Parse(xml);

        var packages = doc.Root!.Elements(Common + "package").ToList();
        Assert.Equal("2", doc.Root.Attribute("packages")!.Value);
        Assert.Equal(2, packages.Count);

        var curl = Assert.Single(packages, p => p.Element(Common + "name")!.Value == "curl");
        var curlLocation = curl.Element(Common + "location")!;
        Assert.Equal("packages/curl-8.6.0-1.fc40.x86_64.rpm", curlLocation.Attribute("href")!.Value);
        Assert.Null(curlLocation.Attribute(XNamespace.Xml + "base"));
        Assert.Equal("HTTP client library", curl.Element(Common + "summary")!.Value);
        Assert.Equal("A command line tool for transferring data.", curl.Element(Common + "description")!.Value);
        Assert.Equal("MIT", curl.Element(Common + "format")!.Element(Rpm + "license")!.Value);

        var wget = Assert.Single(packages, p => p.Element(Common + "name")!.Value == "wget");
        var wgetLocation = wget.Element(Common + "location")!;
        Assert.Equal("packages/wget-1.21-3.fc40.x86_64.rpm", wgetLocation.Attribute("href")!.Value);
        Assert.Null(wgetLocation.Attribute(XNamespace.Xml + "base"));
        Assert.Equal("A utility for retrieving files", wget.Element(Common + "summary")!.Value);
        Assert.Equal("GPL-3.0-or-later", wget.Element(Common + "format")!.Element(Rpm + "license")!.Value);
    }

    private async Task SeedLocalHelloAsync(string orgId)
    {
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "rpm", "hello", purlName: "hello");
        string pvId = await PackageSeeder.InsertVersionAsync(
            _fixture.Store, pkgId,
            version: "2.10-1.el9",
            purl: "pkg:rpm/hello@2.10-1.el9?arch=x86_64",
            blobKey: "rpm/registry/hello-2.10-1.el9.x86_64.rpm",
            checksumSha256: new string('a', 64));

        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync("""
            INSERT INTO rpm_metadata
                (id, package_version_id, owner_kind,
                 rpm_name, epoch, rpm_version, rpm_release, arch,
                 summary, description, installed_size, archive_size, header_start, header_end, rpm_license)
            VALUES
                (lower(hex(randomblob(16))), @pvId, 'package_version',
                 'hello', 0, '2.10', '1.el9', 'x86_64',
                 'A GNU greeting program', 'greeting', 65536, 60000, 440, 2048, 'GPL-3.0-or-later')
            """,
            new { pvId });
    }

    private static byte[] BuildUpstreamPrimaryGz(
        params (string Name, string Ver, string Rel, string Arch, string Href, long PackageSize)[] pkgs)
    {
        var doc = new XDocument(
            new XElement(Common + "metadata",
                new XAttribute(XNamespace.Xmlns + "rpm", Rpm.NamespaceName),
                new XAttribute("packages", pkgs.Length),
                pkgs.Select(p => new XElement(Common + "package",
                    new XAttribute("type", "rpm"),
                    new XElement(Common + "name", p.Name),
                    new XElement(Common + "arch", p.Arch),
                    new XElement(Common + "version",
                        new XAttribute("epoch", 0), new XAttribute("ver", p.Ver), new XAttribute("rel", p.Rel)),
                    new XElement(Common + "checksum",
                        new XAttribute("type", "sha256"), new XAttribute("pkgid", "YES"), new string('b', 64)),
                    new XElement(Common + "size",
                        new XAttribute("package", p.PackageSize),
                        new XAttribute("installed", 1), new XAttribute("archive", 1)),
                    new XElement(Common + "location", new XAttribute("href", p.Href)),
                    new XElement(Common + "format", new XElement(Rpm + "license", "MIT"))))));

        return RpmRepodataService.Gzip(System.Text.Encoding.UTF8.GetBytes(doc.ToString()));
    }

    private static byte[] BuildUpstreamPrimaryGzWithXmlBase(
        params (string Name, string Ver, string Rel, string Arch, string Href, string Summary, string Description, string License)[] pkgs)
    {
        var doc = new XDocument(
            new XElement(Common + "metadata",
                new XAttribute(XNamespace.Xmlns + "rpm", Rpm.NamespaceName),
                new XAttribute("packages", pkgs.Length),
                pkgs.Select(p => new XElement(Common + "package",
                    new XAttribute("type", "rpm"),
                    new XElement(Common + "name", p.Name),
                    new XElement(Common + "arch", p.Arch),
                    new XElement(Common + "version",
                        new XAttribute("epoch", 0), new XAttribute("ver", p.Ver), new XAttribute("rel", p.Rel)),
                    new XElement(Common + "checksum",
                        new XAttribute("type", "sha256"), new XAttribute("pkgid", "YES"), new string('b', 64)),
                    new XElement(Common + "summary", p.Summary),
                    new XElement(Common + "description", p.Description),
                    new XElement(Common + "size",
                        new XAttribute("package", 1), new XAttribute("installed", 1), new XAttribute("archive", 1)),
                    new XElement(Common + "location",
                        new XAttribute(XNamespace.Xml + "base", "https://mirror.example.com/upstream-repo/"),
                        new XAttribute("href", p.Href)),
                    new XElement(Common + "format", new XElement(Rpm + "license", p.License))))));

        return RpmRepodataService.Gzip(System.Text.Encoding.UTF8.GetBytes(doc.ToString()));
    }

    private static byte[] Gunzip(byte[] gz)
    {
        using var gzStream = new GZipStream(new MemoryStream(gz), CompressionMode.Decompress);
        using var ms = new MemoryStream();
        gzStream.CopyTo(ms);
        return ms.ToArray();
    }
}
