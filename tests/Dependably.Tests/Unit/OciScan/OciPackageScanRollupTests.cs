using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.OciScan;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;

namespace Dependably.Tests.Unit.OciScan;

/// <summary>
/// The package list's OCI scan rollup, against the real schema. A proxied image never gets
/// <c>package_version_vulns</c> rows, so every case here seeds only the org's own scan tables:
/// the rollup must read the same per-org facts the version page does, take the worst state across
/// the images the org holds, and never let one org's result colour another's.
/// </summary>
[Trait("Category", "Unit")]
public sealed class OciPackageScanRollupTests : IAsyncLifetime
{
    private const string Repo = "team/app";

    private readonly TestMetadataStore _db = new();
    private OciScanRepository _repo = null!;
    private string _orgA = null!;
    private string _orgB = null!;
    private string _pkgA = null!;
    private int _digestSeq;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        _repo = new OciScanRepository(_db);
        _orgA = await OrgSeeder.InsertAsync(_db, "roll-a");
        _orgB = await OrgSeeder.InsertAsync(_db, "roll-b");
        _pkgA = await PackageSeeder.InsertAsync(_db, _orgA, "oci", Repo, isProxy: true);
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private string NextDigest() => "sha256:" + (++_digestSeq).ToString("x64");

    private async Task<OciScanView> RollupAsync(string orgId, string packageId, bool covered)
    {
        var held = await _repo.GetHeldImageFactsAsync(orgId, [packageId]);
        var images = held.TryGetValue(packageId, out var facts) ? facts : [];
        return OciScanProjection.RollUp(images, covered);
    }

    private async Task<string> ProxiedAsync(string orgId, params double[]? scores)
    {
        string id = await OciScanSeeder.InsertProxiedManifestAsync(_db, orgId, Repo, NextDigest());
        if (scores is not null)
        {
            await OciScanSeeder.InsertScanAsync(_db, orgId, id, proxied: true, 0, scores);
        }

        return id;
    }

    [Fact]
    public async Task ProxiedImageWithFindingsAndNoLinkedAdvisories_RollsUpVulnerable()
    {
        await ProxiedAsync(_orgA, 9.8, 5.0);

        var view = await RollupAsync(_orgA, _pkgA, covered: true);

        Assert.Equal("scanned", view.State);
        Assert.Equal(2, view.FindingCount);
        Assert.Equal(9.8, view.MaxScore);
        await using var conn = await _db.OpenAsync();
        Assert.Equal(0, await conn.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM package_version_vulns"));
    }

    [Fact]
    public async Task ImageWithNoResult_RollsUpUnscanned_WhileTheScannerIsLive_ElseNoFeed()
    {
        await ProxiedAsync(_orgA, scores: null);

        Assert.Equal("unscanned", (await RollupAsync(_orgA, _pkgA, covered: true)).State);
        Assert.Equal("no_feed", (await RollupAsync(_orgA, _pkgA, covered: false)).State);
    }

    [Fact]
    public async Task ScannedWithGapsAndNoFindings_RollsUpPartial()
    {
        string id = await ProxiedAsync(_orgA, scores: null);
        await OciScanSeeder.InsertScanAsync(_db, _orgA, id, proxied: true, gaps: 2);

        var view = await RollupAsync(_orgA, _pkgA, covered: true);

        Assert.Equal(("scanned", 2, 0), (view.State, view.GapCount, view.FindingCount));
    }

    [Fact]
    public async Task OneVulnerableAndOneCleanImage_RollsUpVulnerable()
    {
        await ProxiedAsync(_orgA, 7.5);
        await ProxiedAsync(_orgA, Array.Empty<double>());

        var view = await RollupAsync(_orgA, _pkgA, covered: true);

        Assert.Equal(1, view.FindingCount);
        Assert.Equal(7.5, view.MaxScore);
    }

    [Fact]
    public async Task EveryImageScannedClean_RollsUpClean_TheTwin()
    {
        await ProxiedAsync(_orgA, Array.Empty<double>());
        await ProxiedAsync(_orgA, Array.Empty<double>());

        var view = await RollupAsync(_orgA, _pkgA, covered: true);

        Assert.Equal(new OciScanView("scanned", 0, 0, null), view);
    }

    [Fact]
    public async Task CleanImageBesideAnUnscannedOne_IsNotClean()
    {
        await ProxiedAsync(_orgA, Array.Empty<double>());
        await ProxiedAsync(_orgA, scores: null);

        Assert.Equal("unscanned", (await RollupAsync(_orgA, _pkgA, covered: true)).State);
        Assert.Equal("no_feed", (await RollupAsync(_orgA, _pkgA, covered: false)).State);
    }

    [Fact]
    public async Task HostedAndProxiedImagesBothCount()
    {
        string version = await PackageSeeder.InsertVersionAsync(_db, _pkgA, NextDigest(), "pkg:oci/app@h");
        await OciScanSeeder.InsertScanAsync(_db, _orgA, version, proxied: false, 0, 9.0);
        await ProxiedAsync(_orgA, Array.Empty<double>());

        var held = await _repo.GetHeldImageFactsAsync(_orgA, [_pkgA]);

        Assert.Equal(2, held[_pkgA].Count);
        Assert.Equal(1, (await RollupAsync(_orgA, _pkgA, covered: true)).FindingCount);
    }

    [Fact]
    public async Task ProxiedManifestShadowedByAHostedVersionOfTheSameDigest_IsNotCountedTwice()
    {
        string digest = NextDigest();
        await PackageSeeder.InsertVersionAsync(_db, _pkgA, digest, "pkg:oci/app@h");
        await OciScanSeeder.InsertProxiedManifestAsync(_db, _orgA, Repo, digest);

        var held = await _repo.GetHeldImageFactsAsync(_orgA, [_pkgA]);

        Assert.Single(held[_pkgA]);
    }

    [Fact]
    public async Task TwoOrgsPullingTheSameProxiedImage_EachSeesOnlyItsOwnResult()
    {
        string pkgB = await PackageSeeder.InsertAsync(_db, _orgB, "oci", Repo, isProxy: true);
        string shared = await OciScanSeeder.InsertProxiedManifestAsync(_db, _orgA, Repo, NextDigest());
        await OciScanSeeder.InsertProxiedManifestAsync(_db, _orgB, Repo, "unused", existingId: shared);
        await OciScanSeeder.InsertScanAsync(_db, _orgA, shared, proxied: true, 0, 9.8);
        await OciScanSeeder.InsertScanAsync(_db, _orgB, shared, proxied: true);

        var a = await RollupAsync(_orgA, _pkgA, covered: true);
        var b = await RollupAsync(_orgB, pkgB, covered: true);

        Assert.Equal(1, a.FindingCount);
        Assert.Equal(new OciScanView("scanned", 0, 0, null), b);
    }

    [Fact]
    public async Task AnOrgWithoutItsOwnResult_DoesNotInheritAnotherOrgsScan()
    {
        string pkgB = await PackageSeeder.InsertAsync(_db, _orgB, "oci", Repo, isProxy: true);
        string shared = await OciScanSeeder.InsertProxiedManifestAsync(_db, _orgA, Repo, NextDigest());
        await OciScanSeeder.InsertProxiedManifestAsync(_db, _orgB, Repo, "unused", existingId: shared);
        await OciScanSeeder.InsertScanAsync(_db, _orgA, shared, proxied: true, gaps: 2, 9.8);

        var a = await RollupAsync(_orgA, _pkgA, covered: true);
        var b = await RollupAsync(_orgB, pkgB, covered: true);

        Assert.Equal(new OciScanView("scanned", 2, 1, 9.8), a);
        Assert.Equal(new OciScanView("unscanned", 0, 0, null), b);
        Assert.Equal("no_feed", (await RollupAsync(_orgB, pkgB, covered: false)).State);
    }

    [Fact]
    public async Task AnOrgThatNeverPulledTheImage_HoldsNothingAndReadsFromItsCoverage()
    {
        string pkgB = await PackageSeeder.InsertAsync(_db, _orgB, "oci", Repo, isProxy: true);
        await ProxiedAsync(_orgA, 9.8);

        var heldByB = await _repo.GetHeldImageFactsAsync(_orgB, [pkgB]);

        Assert.Empty(heldByB);
        Assert.Equal("unscanned", (await RollupAsync(_orgB, pkgB, covered: true)).State);
        Assert.Equal("no_feed", (await RollupAsync(_orgB, pkgB, covered: false)).State);
        // Asking with another org's package id returns nothing: the package filter carries org_id.
        Assert.Empty(await _repo.GetHeldImageFactsAsync(_orgB, [_pkgA]));
    }

    [Fact]
    public async Task ManyImages_AreReadInChunks_WithEveryResultAttributed()
    {
        string last = "";
        for (int i = 0; i < 520; i++)
        {
            last = await ProxiedAsync(_orgA, scores: null);
        }

        await OciScanSeeder.InsertScanAsync(_db, _orgA, last, proxied: true, 0, 8.0);

        var view = await RollupAsync(_orgA, _pkgA, covered: true);

        Assert.Equal(1, view.FindingCount);
    }

    [Fact]
    public void RollUp_RanksVulnerablePartialUnscannedNoFeedClean()
    {
        var vuln = new OciScanFacts(0, 2, 6.0);
        var partial = new OciScanFacts(3, 0, null);
        var clean = new OciScanFacts(0, 0, null);

        Assert.Equal(new OciScanView("scanned", 3, 2, 6.0), OciScanProjection.RollUp([clean, partial, vuln, null], true));
        Assert.Equal(new OciScanView("scanned", 3, 0, null), OciScanProjection.RollUp([clean, partial, null], true));
        Assert.Equal("unscanned", OciScanProjection.RollUp([clean, null], true).State);
        Assert.Equal("no_feed", OciScanProjection.RollUp([clean, null], false).State);
        Assert.Equal(new OciScanView("scanned", 0, 0, null), OciScanProjection.RollUp([clean, clean], false));
        Assert.Equal("no_feed", OciScanProjection.RollUp([], false).State);
        Assert.Equal("unscanned", OciScanProjection.RollUp([], true).State);
    }

    [Fact]
    public void RollUp_FindingCountIsTheLargestImagesCount_NotASumAcrossImages()
    {
        // Two tags of one package usually share most advisories, so a sum would count one CVE
        // once per image.
        var more = new OciScanFacts(0, 2, 6.0);
        var fewer = new OciScanFacts(0, 1, 3.0);

        Assert.Equal(new OciScanView("scanned", 0, 2, 6.0), OciScanProjection.RollUp([fewer, more], true));
        Assert.Equal(new OciScanView("scanned", 0, 2, 6.0), OciScanProjection.RollUp([more, fewer], true));
    }
}
