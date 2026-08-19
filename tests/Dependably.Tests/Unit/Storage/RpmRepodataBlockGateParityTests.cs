using System.Xml.Linq;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit.Storage;

/// <summary>
/// RPM repodata carried no block-gate filter, so a blocked package was advertised in
/// <c>primary.xml</c> and then refused at <c>packages/{file}</c>. dnf resolves dependencies out of
/// this document and commits to what it finds, so a listed-but-refused package fails a transaction
/// after resolution rather than being routed around — and dnf reports that as a repository error,
/// not a policy one.
///
/// The filter lives in the shared row loader rather than in each builder, so these tests check
/// every document reads the same filtered set, and that the <c>packages="N"</c> counts agree with
/// the elements actually emitted. A count that disagrees with its element list is a malformed
/// document, and dnf is entitled to reject the whole repository over it.
/// </summary>
[Trait("Category", "Unit")]
public sealed class RpmRepodataBlockGateParityTests : IClassFixture<InMemoryDbFixture>
{
    private static readonly XNamespace Common = "http://linux.duke.edu/metadata/common";
    private static readonly XNamespace Filelists = "http://linux.duke.edu/metadata/filelists";
    private static readonly XNamespace Other = "http://linux.duke.edu/metadata/other";

    private readonly InMemoryDbFixture _fixture;

    public RpmRepodataBlockGateParityTests(InMemoryDbFixture fixture) => _fixture = fixture;

    [Fact]
    public async Task BuildPrimaryAsync_ManuallyBlockedPackage_IsAbsent_AndTheCountAgrees()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        await SeedPackageAsync(orgId, "blocked-pkg", "1.0-1.el9");
        string keepId = await SeedPackageAsync(orgId, "clean-pkg", "2.0-1.el9");
        await BlockAsync(orgId, "blocked-pkg");

        var doc = XDocument.Parse(await Service().BuildPrimaryAsync(orgId, CancellationToken.None));
        var names = doc.Root!.Elements(Common + "package")
            .Select(p => p.Element(Common + "name")!.Value).ToList();

        Assert.Equal(["clean-pkg"], names);
        Assert.Equal("1", doc.Root.Attribute("packages")!.Value);
        Assert.NotNull(keepId);
    }

    /// <summary>
    /// The control: with nothing blocked, both packages are listed. Without it a filter that
    /// dropped everything — or one that failed closed reading settings — would satisfy the test
    /// above while emptying every repository.
    /// </summary>
    [Fact]
    public async Task BuildPrimaryAsync_WithNothingBlocked_ListsEveryPackage()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        await SeedPackageAsync(orgId, "alpha-pkg", "1.0-1.el9");
        await SeedPackageAsync(orgId, "beta-pkg", "2.0-1.el9");

        var doc = XDocument.Parse(await Service().BuildPrimaryAsync(orgId, CancellationToken.None));

        Assert.Equal(2, doc.Root!.Elements(Common + "package").Count());
        Assert.Equal("2", doc.Root.Attribute("packages")!.Value);
    }

    /// <summary>
    /// filelists and other are separate documents built from the same rows. A package present in
    /// one and absent from another is a repository dnf cannot reconcile, so the filter has to
    /// reach all three or none.
    /// </summary>
    [Fact]
    public async Task FilelistsAndOther_ExcludeTheBlockedPackageToo()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        await SeedPackageAsync(orgId, "blocked-pkg", "1.0-1.el9");
        await SeedPackageAsync(orgId, "clean-pkg", "2.0-1.el9");
        await BlockAsync(orgId, "blocked-pkg");

        var svc = Service();
        var filelists = XDocument.Parse(await svc.BuildFilelistsAsync(orgId, CancellationToken.None));
        var other = XDocument.Parse(await svc.BuildOtherAsync(orgId, CancellationToken.None));

        Assert.Equal(
            ["clean-pkg"],
            filelists.Root!.Elements(Filelists + "package").Select(p => p.Attribute("name")!.Value));
        Assert.Equal("1", filelists.Root.Attribute("packages")!.Value);

        Assert.Equal(
            ["clean-pkg"],
            other.Root!.Elements(Other + "package").Select(p => p.Attribute("name")!.Value));
        Assert.Equal("1", other.Root.Attribute("packages")!.Value);
    }

    /// <summary>
    /// A revoked package — withdrawn upstream — is withheld under a blocking policy. Distinct from
    /// the manual arm because it is the gate reading a fact nobody set by hand, which is what makes
    /// it evidence the whole policy core runs here rather than a single hard-coded check.
    /// </summary>
    [Fact]
    public async Task BuildPrimaryAsync_RevokedPackage_IsWithheldUnderABlockingPolicy()
    {
        string orgId = await OrgSeeder.InsertAsync(_fixture.Store, $"o-{Guid.NewGuid():N}");
        string pvId = await SeedPackageAsync(orgId, "revoked-pkg", "1.0-1.el9");
        await SeedPackageAsync(orgId, "clean-pkg", "2.0-1.el9");

        await using (var conn = await _fixture.Store.OpenAsync())
        {
            Assert.Equal(1, await conn.ExecuteAsync(
                "UPDATE package_versions SET revoked_at = @at WHERE id = @id",
                new { at = DateTimeOffset.UnixEpoch.ToUtcIso(), id = pvId }));
            Assert.Equal(1, await conn.ExecuteAsync(
                "UPDATE org_settings SET block_revoked = 'block' WHERE org_id = @orgId", new { orgId }));
        }

        var doc = XDocument.Parse(await Service().BuildPrimaryAsync(orgId, CancellationToken.None));

        Assert.Equal(
            ["clean-pkg"],
            doc.Root!.Elements(Common + "package").Select(p => p.Element(Common + "name")!.Value));
    }

    /// <summary>
    /// One tenant's block must not reach another tenant's repodata. RPM's cross-tenant risk is
    /// higher than most: the document is repository-wide rather than per-coordinate, so a filter
    /// that read block state from the wrong scope would empty or expose an entire repository at
    /// once rather than one package.
    /// </summary>
    [Fact]
    public async Task ABlockInOneTenant_DoesNotAffectAnother()
    {
        string orgA = await OrgSeeder.InsertAsync(_fixture.Store, $"a-{Guid.NewGuid():N}");
        string orgB = await OrgSeeder.InsertAsync(_fixture.Store, $"b-{Guid.NewGuid():N}");
        await SeedPackageAsync(orgA, "shared-pkg", "1.0-1.el9");
        await SeedPackageAsync(orgB, "shared-pkg", "1.0-1.el9");
        await BlockAsync(orgA, "shared-pkg");

        var svc = Service();
        var docA = XDocument.Parse(await svc.BuildPrimaryAsync(orgA, CancellationToken.None));
        var docB = XDocument.Parse(await svc.BuildPrimaryAsync(orgB, CancellationToken.None));

        Assert.Empty(docA.Root!.Elements(Common + "package"));
        Assert.Single(docB.Root!.Elements(Common + "package"));
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private RpmRepodataService Service() => new(
        _fixture.Store, NullLogger<RpmRepodataService>.Instance, TimeProvider.System,
        new OrgRepository(_fixture.Store),
        new VulnerabilityRepository(_fixture.Store, TimeProvider.System));

    private async Task<string> SeedPackageAsync(string orgId, string name, string version)
    {
        string pkgId = await PackageSeeder.InsertAsync(_fixture.Store, orgId, "rpm", name, purlName: name);
        string pvId = await PackageSeeder.InsertVersionAsync(
            _fixture.Store, pkgId,
            version: version,
            purl: $"pkg:rpm/{name}@{version}?arch=x86_64",
            blobKey: $"rpm/registry/{name}-{version}.x86_64.rpm",
            sizeBytes: 1234,
            checksumSha256: new string('a', 64));

        await using var conn = await _fixture.Store.OpenAsync();
        await conn.ExecuteAsync("""
            INSERT INTO rpm_metadata
                (id, package_version_id, owner_kind,
                 rpm_name, epoch, rpm_version, rpm_release, arch,
                 summary, description, build_host, build_time,
                 installed_size, archive_size, header_start, header_end, rpm_license)
            VALUES
                (lower(hex(randomblob(16))), @pvId, 'package_version',
                 @name, 0, '1.0', '1.el9', 'x86_64',
                 'summary', 'description', 'builder.example.com', 1716393600,
                 1024, 900, 440, 2048, 'GPL-3.0-or-later')
            """,
            new { pvId, name });
        return pvId;
    }

    private async Task BlockAsync(string orgId, string purlName)
    {
        await using var conn = await _fixture.Store.OpenAsync();
        int rows = await conn.ExecuteAsync(
            """
            UPDATE package_versions SET manual_block_state = 'blocked'
            WHERE package_id IN (
                SELECT id FROM packages
                WHERE org_id = @orgId AND ecosystem = 'rpm' AND purl_name = @purlName)
            """,
            new { orgId, purlName });

        // A silent no-op would leave the package unblocked and make every following assertion
        // pass for the wrong reason.
        Assert.Equal(1, rows);
    }
}
