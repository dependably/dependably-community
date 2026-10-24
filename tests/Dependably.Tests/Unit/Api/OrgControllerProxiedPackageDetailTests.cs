using System.Collections;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.AspNetCore.Mvc;

namespace Dependably.Tests.Unit.Api;

/// <summary>
/// The package detail endpoint for a package whose versions are all proxied: the package row's
/// counters, each version row's package id, and its licences must agree with the versions the same
/// response lists. A proxied version's only catalogue row is its <c>cache_artifact</c> row, so none
/// of these facts can come from <c>package_versions</c>.
/// </summary>
[Trait("Category", "Unit")]
public sealed class OrgControllerProxiedPackageDetailTests
{
    private const string Name = "@types/react";

    private static async Task<string> SeedProxyFileAsync(
        IMetadataStore db, string orgId, string version, string filename, long downloads,
        string? licenseSpdx = null)
    {
        var repo = new CacheArtifactRepository(db);
        var inserted = await repo.InsertAsync(new CacheArtifact
        {
            Id = Guid.NewGuid().ToString("D"),
            Ecosystem = "npm",
            Name = Name,
            Version = version,
            Filename = filename,
            BlobKey = $"proxy/{Guid.NewGuid():N}",
            ContentHash = "abc123",
            SizeBytes = 10,
        });

        await using var conn = await db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO tenant_artifact_access (org_id, cache_artifact_id, download_count)
            VALUES (@orgId, @id, @downloads)
            """,
            new { orgId, id = inserted.Id, downloads });

        if (licenseSpdx is not null)
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO package_version_licenses
                    (id, cache_artifact_id, owner_kind, license_spdx, source)
                VALUES (@id, @caId, 'cache_artifact', @spdx, 'upstream')
                """,
                new { id = Guid.NewGuid().ToString("N"), caId = inserted.Id, spdx = licenseSpdx });
        }

        return inserted.Id;
    }

    private static T Prop<T>(object? o, string name) =>
        (T)o!.GetType().GetProperty(name)!.GetValue(o)!;

    private static List<object> Versions(OkObjectResult ok) =>
        ((IEnumerable)Prop<object>(ok.Value, "versions")).Cast<object>().ToList();

    [Fact]
    public async Task ProxiedOnlyPackage_CountersMatchVersionsList_AndVersionCarriesPackageIdAndLicence()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "member");
        await s.WithPackageAsync(Name, isProxy: true);
        var b = await s.BuildAsync();
        await SeedProxyFileAsync(b.Db, b.PrimaryOrgId, "19.2.17", "react-19.2.17.tgz", downloads: 195, licenseSpdx: "MIT");

        var ok = Assert.IsType<OkObjectResult>(
            await b.OrgController.GetPackage("npm", "@types%2Freact", CancellationToken.None));

        var pkg = Prop<Package>(ok.Value, "package");
        var versions = Versions(ok);
        object version = Assert.Single(versions);
        Assert.Equal(1, pkg.VersionCount);
        Assert.Equal(195, pkg.TotalDownloads);
        Assert.Equal(pkg.Id, Prop<string>(version, "PackageId"));
        Assert.Equal(new[] { "MIT" }, Prop<string[]>(version, "Licenses"));
        Assert.Equal(195L, Prop<long>(version, "DownloadCount"));
    }

    [Fact]
    public async Task MixedPlanes_CountsDedupeSharedVersion_AndSumDownloadsAcrossBoth()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "member");
        await s.WithPackageAsync(Name, isProxy: true);
        await s.WithPackageVersionAsync(Name, "1.0.0");
        var b = await s.BuildAsync();
        await using (var conn = await b.Db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE package_versions SET download_count = 7 WHERE version = '1.0.0'");
        }

        // 1.0.0 also exists on the proxy plane (counts once); 2.0.0 is proxy-only; the other org's
        // access to 3.0.0 must not leak into this org's counters.
        await SeedProxyFileAsync(b.Db, b.PrimaryOrgId, "1.0.0", "react-1.0.0.tgz", downloads: 3);
        await SeedProxyFileAsync(b.Db, b.PrimaryOrgId, "2.0.0", "react-2.0.0.tgz", downloads: 5, licenseSpdx: "MIT");
        string otherOrg = await Dependably.Tests.Infrastructure.Seeding.OrgSeeder.InsertAsync(b.Db, "other");
        await SeedProxyFileAsync(b.Db, otherOrg, "3.0.0", "react-3.0.0.tgz", downloads: 100);

        var ok = Assert.IsType<OkObjectResult>(
            await b.OrgController.GetPackage("npm", "@types%2Freact", CancellationToken.None));

        var pkg = Prop<Package>(ok.Value, "package");
        var versions = Versions(ok);
        Assert.Equal(2, versions.Count);
        Assert.Equal(versions.Count, pkg.VersionCount);
        Assert.Equal(7 + 3 + 5, pkg.TotalDownloads);
        Assert.All(versions, v => Assert.Equal(pkg.Id, Prop<string>(v, "PackageId")));
    }

    [Fact]
    public async Task ProxiedAdvisories_DetailSeverityCountsAndFlagsMatchTheList()
    {
        await using var s = await ControllerScenario.CreateAsync();
        await s.WithOrgAsync(); await s.WithUserAsync(role: "member");
        await s.WithPackageAsync(Name, isProxy: true);
        var b = await s.BuildAsync();
        string caId = await SeedProxyFileAsync(b.Db, b.PrimaryOrgId, "19.2.17", "react-19.2.17.tgz", downloads: 1);

        string critical = await VulnerabilitySeeder.InsertVulnAsync(
            b.Db, osvId: "GHSA-" + Guid.NewGuid().ToString("N")[..8], packageName: Name, severity: "CRITICAL");
        string high = await VulnerabilitySeeder.InsertVulnAsync(
            b.Db, osvId: "GHSA-" + Guid.NewGuid().ToString("N")[..8], packageName: Name, severity: "HIGH");
        string medium = await VulnerabilitySeeder.InsertVulnAsync(
            b.Db, osvId: "GHSA-" + Guid.NewGuid().ToString("N")[..8], packageName: Name, severity: "MEDIUM");
        string low = await VulnerabilitySeeder.InsertVulnAsync(
            b.Db, osvId: "GHSA-" + Guid.NewGuid().ToString("N")[..8], packageName: Name, severity: "LOW");
        string kev = await VulnerabilitySeeder.InsertVulnAsync(
            b.Db, osvId: "GHSA-" + Guid.NewGuid().ToString("N")[..8], packageName: Name, severity: "HIGH", isKev: true);
        string mal = await VulnerabilitySeeder.InsertVulnAsync(
            b.Db, osvId: "MAL-" + Guid.NewGuid().ToString("N")[..8], packageName: Name, severity: "LOW");
        foreach (string vulnId in new[] { critical, high, medium, low, kev, mal })
        {
            await VulnerabilitySeeder.LinkToCacheArtifactAsync(b.Db, caId, vulnId);
        }

        var detail = Prop<Package>(
            Assert.IsType<OkObjectResult>(
                await b.OrgController.GetPackage("npm", "@types%2Freact", CancellationToken.None)).Value,
            "package");
        var list = await b.OrgController.ListPackages();
        var listed = ((IEnumerable)Prop<object>(Assert.IsType<OkObjectResult>(list).Value, "items"))
            .Cast<Package>().Single();

        Assert.Equal(1, listed.CriticalCount);
        Assert.Equal(2, listed.HighCount);
        Assert.Equal(1, listed.MediumCount);
        Assert.Equal(2, listed.LowCount);
        Assert.True(listed.HasKevVersion);
        Assert.True(listed.HasMaliciousVersion);
        Assert.Equal(listed.CriticalCount, detail.CriticalCount);
        Assert.Equal(listed.HighCount, detail.HighCount);
        Assert.Equal(listed.MediumCount, detail.MediumCount);
        Assert.Equal(listed.LowCount, detail.LowCount);
        Assert.Equal(listed.HasKevVersion, detail.HasKevVersion);
        Assert.Equal(listed.HasMaliciousVersion, detail.HasMaliciousVersion);
    }
}
