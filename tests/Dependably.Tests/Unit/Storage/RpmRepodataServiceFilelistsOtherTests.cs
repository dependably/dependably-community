using System.IO.Compression;
using System.Security.Cryptography;
using System.Xml.Linq;
using Dapper;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit.Storage;

/// <summary>
/// Unit coverage for <see cref="RpmRepodataService.BuildFilelistsAsync"/>,
/// <see cref="RpmRepodataService.BuildOtherAsync"/>, the updated
/// <see cref="RpmRepodataService.BuildRepomd"/> multi-document overload, and
/// <see cref="RpmRepodataService.BuildMergedFilelistsAsync"/>. Tests confirm the XML shape
/// that dnf/yum requires, gz round-trip fidelity, repomd checksum consistency, and tenant
/// isolation.
/// </summary>
[Trait("Category", "Unit")]
public sealed class RpmRepodataServiceFilelistsOtherTests : IClassFixture<InMemoryDbFixture>
{
    private static readonly XNamespace Fl = "http://linux.duke.edu/metadata/filelists";
    private static readonly XNamespace Other = "http://linux.duke.edu/metadata/other";
    private static readonly XNamespace Repo = "http://linux.duke.edu/metadata/repo";
    private static readonly XNamespace Common = "http://linux.duke.edu/metadata/common";
    private static readonly XNamespace Rpm = "http://linux.duke.edu/metadata/rpm";

    private readonly InMemoryDbFixture _fixture;

    public RpmRepodataServiceFilelistsOtherTests(InMemoryDbFixture fixture) => _fixture = fixture;

    // ── BuildFilelistsAsync ────────────────────────────────────────────────────

    [Fact]
    public async Task BuildFilelistsAsync_NoRows_ReturnsEmptyFilelistsDocument()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        var svc = MakeSvc();

        string xml = await svc.BuildFilelistsAsync(orgId, CancellationToken.None);

        var doc = XDocument.Parse(xml);
        Assert.Equal("filelists", doc.Root!.Name.LocalName);
        Assert.Equal(Fl.NamespaceName, doc.Root.Name.NamespaceName);
        Assert.Equal("0", doc.Root.Attribute("packages")!.Value);
        Assert.Empty(doc.Root.Elements(Fl + "package"));
    }

    [Fact]
    public async Task BuildFilelistsAsync_WithFiles_EmitsFileElements()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        await SeedPackageVersionAsync(orgId, filesJson: """
            [{"Path":"/usr/bin/hello","Type":"file"},{"Path":"/usr/share/doc/hello","Type":"dir"}]
            """);
        var svc = MakeSvc();

        string xml = await svc.BuildFilelistsAsync(orgId, CancellationToken.None);

        var doc = XDocument.Parse(xml);
        Assert.Equal("1", doc.Root!.Attribute("packages")!.Value);

        var pkg = Assert.Single(doc.Root.Elements(Fl + "package"));
        Assert.Equal("hello", pkg.Attribute("name")!.Value);
        Assert.Equal("x86_64", pkg.Attribute("arch")!.Value);
        Assert.NotEmpty((string?)pkg.Attribute("pkgid") ?? "");

        var ver = pkg.Element(Fl + "version")!;
        Assert.Equal("0", ver.Attribute("epoch")!.Value);
        Assert.Equal("2.10", ver.Attribute("ver")!.Value);
        Assert.Equal("1.el9", ver.Attribute("rel")!.Value);

        var files = pkg.Elements(Fl + "file").ToList();
        Assert.Equal(2, files.Count);
        Assert.Contains(files, f => f.Value == "/usr/bin/hello" && f.Attribute("type") is null);
        Assert.Contains(files, f => f.Value == "/usr/share/doc/hello" && (string?)f.Attribute("type") == "dir");
    }

    [Fact]
    public async Task BuildFilelistsAsync_GhostFiles_EmitTypeAttribute()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        await SeedPackageVersionAsync(orgId, filesJson: """
            [{"Path":"/etc/hello.conf","Type":"ghost"}]
            """);
        var svc = MakeSvc();

        string xml = await svc.BuildFilelistsAsync(orgId, CancellationToken.None);

        var doc = XDocument.Parse(xml);
        var pkg = Assert.Single(doc.Root!.Elements(Fl + "package"));
        var file = Assert.Single(pkg.Elements(Fl + "file"));
        Assert.Equal("ghost", (string?)file.Attribute("type"));
    }

    [Fact]
    public async Task BuildFilelistsAsync_EmptyFilesJson_EmitsPackageWithNoFileElements()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        await SeedPackageVersionAsync(orgId, filesJson: "[]");
        var svc = MakeSvc();

        string xml = await svc.BuildFilelistsAsync(orgId, CancellationToken.None);

        var doc = XDocument.Parse(xml);
        Assert.Equal("1", doc.Root!.Attribute("packages")!.Value);
        var pkg = Assert.Single(doc.Root.Elements(Fl + "package"));
        Assert.Empty(pkg.Elements(Fl + "file"));
    }

    [Fact]
    public async Task BuildFilelistsAsync_FiltersByTenant()
    {
        string orgA = await OrgSeeder.InsertAsync(_fixture.Store, $"a-{Guid.NewGuid():N}");
        string orgB = await OrgSeeder.InsertAsync(_fixture.Store, $"b-{Guid.NewGuid():N}");

        await SeedPackageVersionAsync(orgB, filesJson: """
            [{"Path":"/usr/bin/from-b","Type":"file"}]
            """, name: "from-b");
        var svc = MakeSvc();

        string xmlA = await svc.BuildFilelistsAsync(orgA, CancellationToken.None);
        Assert.Equal("0", XDocument.Parse(xmlA).Root!.Attribute("packages")!.Value);

        string xmlB = await svc.BuildFilelistsAsync(orgB, CancellationToken.None);
        Assert.Equal("1", XDocument.Parse(xmlB).Root!.Attribute("packages")!.Value);
    }

    // ── BuildOtherAsync ────────────────────────────────────────────────────────

    [Fact]
    public async Task BuildOtherAsync_NoRows_ReturnsEmptyOtherDocument()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        var svc = MakeSvc();

        string xml = await svc.BuildOtherAsync(orgId, CancellationToken.None);

        var doc = XDocument.Parse(xml);
        Assert.Equal("otherdata", doc.Root!.Name.LocalName);
        Assert.Equal(Other.NamespaceName, doc.Root.Name.NamespaceName);
        Assert.Equal("0", doc.Root.Attribute("packages")!.Value);
        Assert.Empty(doc.Root.Elements(Other + "package"));
    }

    [Fact]
    public async Task BuildOtherAsync_WithChangelogs_EmitsChangelogElements()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        await SeedPackageVersionAsync(orgId, changelogsJson: """
            [{"Author":"Jane <jane@example.com>","Date":1716393600,"Text":"- Initial release"},
             {"Author":"Bob <bob@example.com>","Date":1715000000,"Text":"- First build"}]
            """);
        var svc = MakeSvc();

        string xml = await svc.BuildOtherAsync(orgId, CancellationToken.None);

        var doc = XDocument.Parse(xml);
        Assert.Equal("1", doc.Root!.Attribute("packages")!.Value);

        var pkg = Assert.Single(doc.Root.Elements(Other + "package"));
        Assert.Equal("hello", pkg.Attribute("name")!.Value);
        Assert.Equal("x86_64", pkg.Attribute("arch")!.Value);

        var changelogs = pkg.Elements(Other + "changelog").ToList();
        Assert.Equal(2, changelogs.Count);
        Assert.Equal("Jane <jane@example.com>", changelogs[0].Attribute("author")!.Value);
        Assert.Equal("1716393600", changelogs[0].Attribute("date")!.Value);
        Assert.Equal("- Initial release", changelogs[0].Value);
    }

    [Fact]
    public async Task BuildOtherAsync_EmptyChangelogsJson_EmitsPackageWithNoChangelogs()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        await SeedPackageVersionAsync(orgId, changelogsJson: "[]");
        var svc = MakeSvc();

        string xml = await svc.BuildOtherAsync(orgId, CancellationToken.None);

        var doc = XDocument.Parse(xml);
        Assert.Equal("1", doc.Root!.Attribute("packages")!.Value);
        var pkg = Assert.Single(doc.Root.Elements(Other + "package"));
        Assert.Empty(pkg.Elements(Other + "changelog"));
    }

    // ── BuildRepomd multi-doc ─────────────────────────────────────────────────

    [Fact]
    public void BuildRepomd_WithFilelistsAndOther_EmitsAllThreeDataEntries()
    {
        byte[] primaryGz = new byte[] { 1, 2, 3 };
        byte[] filelistsGz = new byte[] { 4, 5, 6 };
        byte[] otherGz = new byte[] { 7, 8, 9 };

        string xml = RpmRepodataService.BuildRepomd(primaryGz, TimeProvider.System.GetUtcNow(), filelistsGz, otherGz);
        var doc = XDocument.Parse(xml);

        var dataElements = doc.Root!.Elements(Repo + "data").ToList();
        Assert.Equal(3, dataElements.Count);

        var types = dataElements.Select(e => (string?)e.Attribute("type")).OrderBy(t => t).ToList();
        Assert.Equal(new[] { "filelists", "other", "primary" }, types);

        foreach (var data in dataElements)
        {
            Assert.NotNull(data.Element(Repo + "checksum"));
            Assert.NotNull(data.Element(Repo + "location"));
            Assert.NotNull(data.Element(Repo + "timestamp"));
            Assert.NotNull(data.Element(Repo + "size"));
        }
    }

    [Fact]
    public void BuildRepomd_ChecksumMatchesGzContent()
    {
        byte[] primaryGz = new byte[] { 1, 2, 3 };
        byte[] filelistsGz = new byte[] { 4, 5, 6 };
        byte[] otherGz = new byte[] { 7, 8, 9 };

        string xml = RpmRepodataService.BuildRepomd(primaryGz, TimeProvider.System.GetUtcNow(), filelistsGz, otherGz);
        var doc = XDocument.Parse(xml);

        foreach (var data in doc.Root!.Elements(Repo + "data"))
        {
            string type = (string?)data.Attribute("type") ?? "";
            byte[] gzBytes = type switch
            {
                "primary" => primaryGz,
                "filelists" => filelistsGz,
                "other" => otherGz,
                _ => throw new InvalidOperationException($"Unexpected type: {type}"),
            };
            string expectedSha = Convert.ToHexString(SHA256.HashData(gzBytes)).ToLowerInvariant();
            Assert.Equal(expectedSha, data.Element(Repo + "checksum")!.Value);
            Assert.Equal(gzBytes.Length.ToString(), data.Element(Repo + "size")!.Value);
        }
    }

    [Fact]
    public void BuildRepomd_HrefsPointToRepodataDirectory()
    {
        byte[] gz = new byte[] { 1 };
        string xml = RpmRepodataService.BuildRepomd(gz, TimeProvider.System.GetUtcNow(), gz, gz);
        var doc = XDocument.Parse(xml);

        foreach (var data in doc.Root!.Elements(Repo + "data"))
        {
            string href = (string?)data.Element(Repo + "location")?.Attribute("href") ?? "";
            Assert.StartsWith("repodata/", href);
            Assert.EndsWith(".xml.gz", href);
        }
    }

    [Fact]
    public void BuildRepomd_BackwardCompatible_SingleArgStillProducesOneEntry()
    {
        byte[] primaryGz = new byte[] { 1, 2, 3 };

        string xml = RpmRepodataService.BuildRepomd(primaryGz, TimeProvider.System.GetUtcNow());
        var doc = XDocument.Parse(xml);

        var dataElements = doc.Root!.Elements(Repo + "data").ToList();
        Assert.Single(dataElements);
        Assert.Equal("primary", (string?)dataElements[0].Attribute("type"));
    }

    [Fact]
    public void BuildRepomd_WithExtraEntries_IncludesThemInOutput()
    {
        byte[] primaryGz = new byte[] { 1 };
        var extraEntry = new XElement(Repo + "data",
            new XAttribute("type", "updateinfo"),
            new XElement(Repo + "location", new XAttribute("href", "repodata/abc123-updateinfo.xml.gz")));

        string xml = RpmRepodataService.BuildRepomd(primaryGz, TimeProvider.System.GetUtcNow(), extraEntries: new[] { extraEntry });
        var doc = XDocument.Parse(xml);

        var types = doc.Root!.Elements(Repo + "data")
            .Select(e => (string?)e.Attribute("type")).ToList();
        Assert.Contains("primary", types);
        Assert.Contains("updateinfo", types);
    }

    // ── End-to-end: publish → rebuild asserts primary + filelists + other ──────

    [Fact]
    public async Task PublishThenRebuild_RepomdContainsPrimaryFilelistsOther()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        await SeedPackageVersionAsync(orgId,
            filesJson: """[{"Path":"/usr/bin/hello","Type":"file"}]""",
            changelogsJson: """[{"Author":"A <a@b.com>","Date":1716393600,"Text":"- release"}]""");

        var svc = MakeSvc();
        string primary = await svc.BuildPrimaryAsync(orgId, CancellationToken.None);
        byte[] primaryGz = RpmRepodataService.Gzip(System.Text.Encoding.UTF8.GetBytes(primary));
        string filelists = await svc.BuildFilelistsAsync(orgId, CancellationToken.None);
        byte[] filelistsGz = RpmRepodataService.Gzip(System.Text.Encoding.UTF8.GetBytes(filelists));
        string other = await svc.BuildOtherAsync(orgId, CancellationToken.None);
        byte[] otherGz = RpmRepodataService.Gzip(System.Text.Encoding.UTF8.GetBytes(other));

        string repomdXml = RpmRepodataService.BuildRepomd(primaryGz, TimeProvider.System.GetUtcNow(), filelistsGz, otherGz);
        var doc = XDocument.Parse(repomdXml);

        var types = doc.Root!.Elements(Repo + "data")
            .Select(e => (string?)e.Attribute("type")).OrderBy(t => t).ToList();
        Assert.Equal(new[] { "filelists", "other", "primary" }, types);

        // Checksums must match actual gz content.
        var primaryData = doc.Root.Elements(Repo + "data").Single(e => (string?)e.Attribute("type") == "primary");
        Assert.Equal(
            Convert.ToHexString(SHA256.HashData(primaryGz)).ToLowerInvariant(),
            primaryData.Element(Repo + "checksum")!.Value);

        var filelistsData = doc.Root.Elements(Repo + "data").Single(e => (string?)e.Attribute("type") == "filelists");
        Assert.Equal(
            Convert.ToHexString(SHA256.HashData(filelistsGz)).ToLowerInvariant(),
            filelistsData.Element(Repo + "checksum")!.Value);
    }

    // ── BuildMergedFilelistsAsync ──────────────────────────────────────────────

    [Fact]
    public async Task BuildMergedFilelistsAsync_UnionsLocalAndUpstream_LocalShadowsOnNevraCollision()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        await SeedPackageVersionAsync(orgId,
            filesJson: """[{"Path":"/usr/local/bin/hello","Type":"file"}]""");

        // Upstream has same hello (shadowed) + unique tree.
        byte[] upstreamFilelistsGz = BuildUpstreamFilelistsGz(
            ("hello", "2.10", "1.el9", "x86_64", new[] { "/usr/bin/hello-upstream" }),
            ("tree", "2.1.1", "1.el9", "x86_64", new[] { "/usr/bin/tree" }));

        var svc = MakeSvc();
        string xml = await svc.BuildMergedFilelistsAsync(orgId, upstreamFilelistsGz, CancellationToken.None);

        var doc = XDocument.Parse(xml);
        var packages = doc.Root!.Elements(Fl + "package").ToList();
        Assert.Equal("2", doc.Root.Attribute("packages")!.Value);
        Assert.Equal(2, packages.Count);

        // hello comes from local (has /usr/local/bin/hello, not /usr/bin/hello-upstream).
        var hello = Assert.Single(packages, p => (string?)p.Attribute("name") == "hello");
        Assert.Contains(hello.Elements(Fl + "file"), f => f.Value == "/usr/local/bin/hello");
        Assert.DoesNotContain(hello.Elements(Fl + "file"), f => f.Value == "/usr/bin/hello-upstream");

        // tree comes from upstream.
        var tree = Assert.Single(packages, p => (string?)p.Attribute("name") == "tree");
        Assert.Contains(tree.Elements(Fl + "file"), f => f.Value == "/usr/bin/tree");
    }

    [Fact]
    public async Task BuildMergedFilelistsAsync_NoUpstreamHello_LocalOnlyAppears()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        await SeedPackageVersionAsync(orgId,
            filesJson: """[{"Path":"/usr/bin/hello","Type":"file"}]""");

        byte[] upstreamFilelistsGz = BuildUpstreamFilelistsGz(
            ("tree", "2.1.1", "1.el9", "x86_64", new[] { "/usr/bin/tree" }));

        var svc = MakeSvc();
        string xml = await svc.BuildMergedFilelistsAsync(orgId, upstreamFilelistsGz, CancellationToken.None);

        var doc = XDocument.Parse(xml);
        Assert.Equal("2", doc.Root!.Attribute("packages")!.Value);
        Assert.Contains(doc.Root.Elements(Fl + "package"), p => (string?)p.Attribute("name") == "hello");
        Assert.Contains(doc.Root.Elements(Fl + "package"), p => (string?)p.Attribute("name") == "tree");
    }

    // ── Gz round-trip ─────────────────────────────────────────────────────────

    [Fact]
    public async Task BuildFilelistsAsync_GzRoundTrip()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        var svc = MakeSvc();

        string xml = await svc.BuildFilelistsAsync(orgId, CancellationToken.None);
        byte[] gz = RpmRepodataService.Gzip(System.Text.Encoding.UTF8.GetBytes(xml));

        Assert.Equal(0x1f, gz[0]);
        Assert.Equal(0x8b, gz[1]);

        string roundTripped = System.Text.Encoding.UTF8.GetString(Gunzip(gz));
        Assert.Equal(xml, roundTripped);
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private RpmRepodataService MakeSvc()
        => new(_fixture.Store, NullLogger<RpmRepodataService>.Instance, TimeProvider.System);

    private async Task<string> SeedPackageVersionAsync(
        string orgId,
        string name = "hello",
        string filesJson = "[]",
        string changelogsJson = "[]",
        string rpmVersion = "2.10",
        string rpmRelease = "1.el9",
        string arch = "x86_64")
    {
        // Embed a short orgId suffix in the PURL version tag to avoid collisions on the
        // globally-unique package_versions.purl index across tests that share the DB fixture.
        string safeName = name.ToLowerInvariant();
        string purlVer = $"{rpmVersion}-{rpmRelease}+{orgId[..8]}";
        string pkgId = await PackageSeeder.InsertAsync(
            _fixture.Store, orgId, "rpm", name, purlName: safeName);
        string pvId = await PackageSeeder.InsertVersionAsync(
            _fixture.Store, pkgId,
            version: $"{rpmVersion}-{rpmRelease}",
            purl: $"pkg:rpm/{safeName}@{purlVer}?arch={arch}",
            blobKey: $"rpm/registry/{name}-{rpmVersion}-{rpmRelease}.{arch}.rpm",
            sizeBytes: 12345,
            checksumSha256: new string('a', 64));

        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO rpm_metadata
                (id, package_version_id, owner_kind,
                 rpm_name, epoch, rpm_version, rpm_release, arch,
                 installed_size, archive_size, header_start, header_end, rpm_license,
                 files_json, changelogs_json)
            VALUES
                (lower(hex(randomblob(16))), @pvId, 'package_version',
                 @name, 0, @rpmVersion, @rpmRelease, @arch,
                 65536, 60000, 440, 2048, 'GPL-3.0-or-later',
                 @filesJson, @changelogsJson)
            """,
            new { pvId, name, rpmVersion, rpmRelease, arch, filesJson, changelogsJson });
        return pvId;
    }

    private static byte[] BuildUpstreamFilelistsGz(
        params (string Name, string Ver, string Rel, string Arch, string[] Files)[] pkgs)
    {
        var doc = new XDocument(
            new XElement(Fl + "filelists",
                new XAttribute("packages", pkgs.Length),
                pkgs.Select(p => new XElement(Fl + "package",
                    new XAttribute("pkgid", new string('b', 64)),
                    new XAttribute("name", p.Name),
                    new XAttribute("arch", p.Arch),
                    new XElement(Fl + "version",
                        new XAttribute("epoch", 0),
                        new XAttribute("ver", p.Ver),
                        new XAttribute("rel", p.Rel)),
                    p.Files.Select(f => new XElement(Fl + "file", f))))));

        return RpmRepodataService.Gzip(System.Text.Encoding.UTF8.GetBytes(doc.ToString()));
    }

    private static byte[] Gunzip(byte[] gz)
    {
        using var ms = new MemoryStream(gz);
        using var gunzip = new GZipStream(ms, CompressionMode.Decompress);
        using var outMs = new MemoryStream();
        gunzip.CopyTo(outMs);
        return outMs.ToArray();
    }
}
