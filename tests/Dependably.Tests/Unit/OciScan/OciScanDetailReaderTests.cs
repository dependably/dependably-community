using System.Text.Json;
using Dependably.Api;
using Dependably.Infrastructure;
using Dependably.Infrastructure.OciScan;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;

namespace Dependably.Tests.Unit.OciScan;

/// <summary>
/// The scan-detail read against the real schema: which owner it resolves, what state it
/// reports, how it pages and caps, and that it never reaches past the caller's org.
/// </summary>
[Trait("Category", "Unit")]
public sealed class OciScanDetailReaderTests : IAsyncLifetime
{
    private const string Repo = "team/app";
    private const string Digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    private const string OtherDigest = "sha256:2222222222222222222222222222222222222222222222222222222222222222";

    private static readonly JsonSerializerOptions WebJson = new(JsonSerializerDefaults.Web);

    private readonly TestMetadataStore _db = new();
    private readonly FakeCoverage _coverage = new();
    private OciScanRepository _repo = null!;
    private OciScanDetailReader _reader = null!;
    private string _orgA = null!;
    private string _orgB = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        _repo = new OciScanRepository(_db);
        _reader = new OciScanDetailReader(_repo, _coverage);
        _orgA = await OrgSeeder.InsertAsync(_db, "detail-a");
        _orgB = await OrgSeeder.InsertAsync(_db, "detail-b");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private Task<(OciScanDetailOutcome Outcome, OciScanDetail? Detail)> ReadAsync(
        string orgId, string digest = Digest, string? platform = null, bool affectedOnly = true, int offset = 0,
        int limit = OciScanDetailReader.DefaultLimit)
        => _reader.ReadAsync(orgId, Repo, digest, platform, affectedOnly, offset, limit);

    [Fact]
    public async Task HostedResult_CarriesEveryPlatform_OnePlatformsAffectedComponents_AndAdvisoriesOnce()
    {
        var owner = OciScanOwner.Hosted(await OciScanSeeder.HostedImageAsync(_db, _orgA, Repo, Digest));
        await OciScanSeeder.ResultAsync(_db, _orgA, owner, "linux/arm64", ["<b>rpm</b> packages: no OSV ecosystem"],
        [
            new SeedComponent("arm-only", 0, [new SeedFinding("DSA-9001-1")]),
        ]);
        await OciScanSeeder.ResultAsync(_db, _orgA, owner, "linux/amd64", [],
        [
            new SeedComponent("libssl3", 0, [new SeedFinding("DSA-9001-1", "reachable"), new SeedFinding("GHSA-low", "not_observed", "LOW", 2.0, "no call path", "high")],
                SourceName: "openssl", LayerInstruction: "RUN apt-get install -y libssl3"),
            new SeedComponent("libcrypto", 1, [new SeedFinding("DSA-9001-1", "unknown")], SourceName: "openssl"),
            new SeedComponent("zlib", 0, []),
        ]);

        var (outcome, detail) = await ReadAsync(_orgA);

        Assert.Equal(OciScanDetailOutcome.Found, outcome);
        Assert.Equal("scanned", detail!.State);
        Assert.Null(detail.Job);
        Assert.Equal(["linux/amd64", "linux/arm64"], detail.Platforms.Select(p => p.Platform));
        var amd = detail.Platforms[0];
        Assert.Equal((3, 2, true), (amd.ComponentCount, amd.AffectedComponentCount, amd.ClosureBounded));
        // Gap text verbatim, markup included: it is data.
        Assert.Equal(["<b>rpm</b> packages: no OSV ecosystem"], detail.Platforms[1].Gaps);

        var page = detail.Components!;
        Assert.Equal("linux/amd64", page.Platform);
        Assert.Equal(2, page.Total);
        Assert.Equal(["libssl3", "libcrypto"], page.Items.Select(c => c.Name));
        var ssl = page.Items[0];
        Assert.Equal(("openssl", 0, "RUN apt-get install -y libssl3"), (ssl.SourceName, ssl.LayerIndex, ssl.LayerInstruction));
        Assert.Null(ssl.InEntrypointClosure);
        Assert.Equal(2, ssl.FindingCount);
        Assert.Equal(["DSA-9001-1", "GHSA-low"], ssl.Findings.Select(f => f.OsvId));
        Assert.Equal("reachable", ssl.Findings[0].Reachability);
        Assert.Equal(("not_observed", "no call path", "high"),
            (ssl.Findings[1].Reachability, ssl.Findings[1].NotObservedBasis, ssl.Findings[1].Confidence));

        // Two components share an advisory; it is described once.
        Assert.Equal(["DSA-9001-1", "GHSA-low"], detail.Advisories.Keys.Order(StringComparer.Ordinal));
        Assert.Equal("HIGH", detail.Advisories["DSA-9001-1"].Severity);
        Assert.Equal(["CVE-DSA-9001-1"], detail.Advisories["DSA-9001-1"].Aliases);
    }

    [Fact]
    public async Task AffectedOnlyOff_ListsTheFullInventory_AndThePlatformCanBeChosen()
    {
        var owner = OciScanOwner.Hosted(await OciScanSeeder.HostedImageAsync(_db, _orgA, Repo, Digest));
        await OciScanSeeder.ResultAsync(_db, _orgA, owner, "linux/amd64", [],
        [
            new SeedComponent("b-clean", 0, []),
            new SeedComponent("a-clean", 0, []),
            new SeedComponent("late-clean", null, []),
            new SeedComponent("vuln", 3, [new SeedFinding("DSA-9002-1")]),
        ]);
        await OciScanSeeder.ResultAsync(_db, _orgA, owner, "linux/arm64", [], [new SeedComponent("arm", 0, [])]);

        var all = (await ReadAsync(_orgA, affectedOnly: false)).Detail!.Components!;
        Assert.Equal(4, all.Total);
        // Affected first, then layer index (unknown layer last), then name.
        Assert.Equal(["vuln", "a-clean", "b-clean", "late-clean"], all.Items.Select(c => c.Name));

        var paged = (await ReadAsync(_orgA, affectedOnly: false, offset: 1, limit: 2)).Detail!.Components!;
        Assert.Equal((4, 1, 2), (paged.Total, paged.Offset, paged.Limit));
        Assert.Equal(["a-clean", "b-clean"], paged.Items.Select(c => c.Name));

        var clamped = (await ReadAsync(_orgA, limit: 100_000)).Detail!.Components!;
        Assert.Equal(OciScanDetailReader.MaxLimit, clamped.Limit);

        var arm = (await ReadAsync(_orgA, platform: "linux/arm64", affectedOnly: false)).Detail!.Components!;
        Assert.Equal(["arm"], arm.Items.Select(c => c.Name));

        Assert.Equal(OciScanDetailOutcome.UnknownPlatform, (await ReadAsync(_orgA, platform: "linux/s390x")).Outcome);
    }

    [Fact]
    public async Task FindingsPerComponent_AreCappedWorstFirst_AndTheFullCountTravelsBeside_Them()
    {
        var owner = OciScanOwner.Hosted(await OciScanSeeder.HostedImageAsync(_db, _orgA, Repo, Digest));
        var findings = Enumerable.Range(0, 55)
            .Select(i => new SeedFinding($"DSA-{i:D4}-1", "unknown", "LOW", 2.0))
            .Append(new SeedFinding("GHSA-unscored", "reachable", null, null))
            .Append(new SeedFinding("GHSA-crit-notobs", "not_observed", "CRITICAL", 9.8))
            .Append(new SeedFinding("GHSA-crit-reach", "reachable", "CRITICAL", 9.8))
            .ToList();
        await OciScanSeeder.ResultAsync(_db, _orgA, owner, "linux/amd64", [], [new SeedComponent("busy", 0, findings)]);

        var item = Assert.Single((await ReadAsync(_orgA)).Detail!.Components!.Items);

        Assert.Equal(58, item.FindingCount);
        Assert.Equal(OciScanDetailReader.MaxFindingsPerComponent, item.Findings.Count);
        Assert.Equal("GHSA-crit-reach", item.Findings[0].OsvId);
        Assert.Equal("GHSA-crit-notobs", item.Findings[1].OsvId);
        // An unscored finding sorts after every scored one, so the cap drops it here.
        Assert.DoesNotContain(item.Findings, f => f.OsvId == "GHSA-unscored");
    }

    [Fact]
    public async Task AHostedImageWithNoResult_ReadsUnscanned_EvenWhenItsProxiedTwinHasOne_WhileLookupAnswersFromIt()
    {
        _coverage.Covered = true;
        var hosted = OciScanOwner.Hosted(await OciScanSeeder.HostedImageAsync(_db, _orgA, Repo, Digest));
        var proxied = OciScanOwner.Proxied(await OciScanSeeder.ProxiedManifestAsync(_db, Repo, Digest));
        await OciScanSeeder.GrantAsync(_db, _orgA, proxied.Id);
        await OciScanSeeder.ResultAsync(_db, _orgA, proxied, "linux/amd64", [], [new SeedComponent("p", 0, [new SeedFinding("DSA-9003-1")])]);

        Assert.Equal(hosted, await _repo.ResolveImageOwnerAsync(_orgA, Repo, Digest));
        var (_, detail) = await ReadAsync(_orgA);
        Assert.Equal("unscanned", detail!.State);
        Assert.Empty(detail.Platforms);
        Assert.Null(detail.Components);

        // The lookup's rule is unchanged: it answers from whichever owner has a result.
        var lookup = await _repo.FindLookupScanAsync(_orgA, Repo, Digest);
        Assert.NotNull(lookup);
        Assert.Equal("DSA-9003-1", Assert.Single(lookup.Advisories).OsvId);
    }

    [Fact]
    public async Task AProxiedImage_IsReadThroughTheOrgsOwnAccess_AndOnlyItsOwnResult()
    {
        var proxied = OciScanOwner.Proxied(await OciScanSeeder.ProxiedManifestAsync(_db, Repo, Digest));
        await OciScanSeeder.GrantAsync(_db, _orgA, proxied.Id);
        await OciScanSeeder.ResultAsync(_db, _orgA, proxied, "linux/amd64", ["a-gap"], [new SeedComponent("a-comp", 0, [new SeedFinding("DSA-A-1")])]);

        // Not pulled by B: invisible, whatever A's scanner stored.
        Assert.Equal(OciScanDetailOutcome.NotFound, (await ReadAsync(_orgB)).Outcome);

        // Twin: B pulls the same manifest and has its own result. Each sees only its own rows.
        await OciScanSeeder.GrantAsync(_db, _orgB, proxied.Id);
        await OciScanSeeder.ResultAsync(_db, _orgB, proxied, "linux/amd64", [], [new SeedComponent("b-comp", 0, [new SeedFinding("DSA-B-1")])]);

        var a = (await ReadAsync(_orgA)).Detail!;
        var b = (await ReadAsync(_orgB)).Detail!;
        Assert.Equal(["a-comp"], a.Components!.Items.Select(c => c.Name));
        Assert.Equal(["b-comp"], b.Components!.Items.Select(c => c.Name));
        Assert.Equal(["a-gap"], Assert.Single(a.Platforms).Gaps);
        Assert.Empty(Assert.Single(b.Platforms).Gaps);
        Assert.Equal(1, Assert.Single(b.Platforms).ComponentCount);
        Assert.Equal(["DSA-B-1"], b.Advisories.Keys);
    }

    [Fact]
    public async Task AnotherOrgsHostedImage_AndAnUnknownDigest_AreNotFound()
    {
        var owner = OciScanOwner.Hosted(await OciScanSeeder.HostedImageAsync(_db, _orgA, Repo, Digest));
        await OciScanSeeder.ResultAsync(_db, _orgA, owner, "linux/amd64", [], [new SeedComponent("x", 0, [])]);

        Assert.Equal(OciScanDetailOutcome.Found, (await ReadAsync(_orgA)).Outcome);
        Assert.Equal(OciScanDetailOutcome.NotFound, (await ReadAsync(_orgB)).Outcome);
        Assert.Equal(OciScanDetailOutcome.NotFound, (await ReadAsync(_orgA, OtherDigest)).Outcome);
    }

    [Fact]
    public async Task WithoutAResult_TheJobStateShows_ButNeverItsError()
    {
        _coverage.Covered = true;
        const string secret = "scanner-said: token=hunter2 at /var/lib/secret";
        var none = OciScanOwner.Hosted(await OciScanSeeder.HostedImageAsync(_db, _orgA, Repo, Digest));
        var pending = OciScanOwner.Hosted(await OciScanSeeder.HostedImageAsync(_db, _orgA, Repo, OtherDigest));
        string failedDigest = "sha256:" + new string('3', 64);
        var failed = OciScanOwner.Hosted(await OciScanSeeder.HostedImageAsync(_db, _orgA, Repo, failedDigest));
        await OciScanSeeder.JobAsync(_db, _orgA, pending, Repo, OtherDigest, "pending", 2, secret);
        await OciScanSeeder.JobAsync(_db, _orgA, failed, Repo, failedDigest, "failed", 5, secret);
        // Another org's job for the same image row is not this org's job.
        await OciScanSeeder.JobAsync(_db, _orgB, none, Repo, Digest, "failed", 9, secret);

        var noneDetail = (await ReadAsync(_orgA)).Detail!;
        var pendingDetail = (await ReadAsync(_orgA, OtherDigest)).Detail!;
        var failedDetail = (await ReadAsync(_orgA, failedDigest)).Detail!;

        // Checked first, so a leak fails on the leak rather than on a state it happens to garble.
        foreach (var d in new[] { noneDetail, pendingDetail, failedDetail })
        {
            Assert.DoesNotContain("hunter2", JsonSerializer.Serialize(d, WebJson));
        }

        Assert.Equal(("unscanned", "none", (int?)null), (noneDetail.State, noneDetail.Job!.State, noneDetail.Job.Attempts));
        Assert.Equal(("pending", (int?)2), (pendingDetail.Job!.State, pendingDetail.Job.Attempts));
        Assert.Equal(("failed", (int?)5), (failedDetail.Job!.State, failedDetail.Job.Attempts));

        Assert.DoesNotContain("attempts", JsonSerializer.Serialize(noneDetail.Job, WebJson));
    }

    [Fact]
    public async Task WithoutALiveScanner_OrWithScanningOff_TheImageHasNoFeed()
    {
        var owner = OciScanOwner.Hosted(await OciScanSeeder.HostedImageAsync(_db, _orgA, Repo, Digest));
        await OciScanSeeder.JobAsync(_db, _orgA, owner, Repo, Digest, "pending", 1, null);

        var quiet = (await ReadAsync(_orgA)).Detail!;
        Assert.Equal("no_feed", quiet.State);
        Assert.Null(quiet.Job);

        await OciScanSeeder.ResultAsync(_db, _orgA, owner, "linux/amd64", [], [new SeedComponent("x", 0, [])]);
        Assert.Equal("scanned", (await ReadAsync(_orgA)).Detail!.State);

        // Scanning off: the version row reads no result at all, and neither does the detail.
        _coverage.Enabled = false;
        var (offOutcome, offDetail) = await ReadAsync(_orgA);
        Assert.Equal(OciScanDetailOutcome.Found, offOutcome);
        Assert.Equal("no_feed", offDetail!.State);
        Assert.Empty(offDetail.Platforms);
        Assert.Equal(OciScanDetailOutcome.NotFound, (await ReadAsync(_orgA, OtherDigest)).Outcome);
    }

    [Theory]
    [InlineData(false, false, "no_feed", "no_feed")]
    [InlineData(false, true, "unscanned", "unscanned")]
    [InlineData(true, false, "scanned", "clean")]
    [InlineData(true, true, "scanned", "clean")]
    public void TheDetailState_FollowsTheSameInputsAsTheVersionStatus(
        bool hasResult, bool covered, string expectedState, string expectedStatus)
    {
        var facts = hasResult ? new OciScanFacts(0, 0, null) : null;
        string status = PackageVersionStatus.ComputeOciVersionStatus(new PackageVersion(), facts, covered, 10.0, "off");

        Assert.Equal(expectedStatus, status);
        // One helper: the detail read, the version row's projection and the package rollup.
        Assert.Equal(expectedState, OciScanProjection.State(hasResult, covered));
        Assert.Equal(expectedState, OciScanProjection.Project(facts, covered).State);
        Assert.Equal(expectedState, OciScanProjection.RollUp([facts], covered).State);
    }

    [Fact]
    public async Task TheDetailReadsTheSameStateAsTheProjection_ForEachInput()
    {
        var owner = OciScanOwner.Hosted(await OciScanSeeder.HostedImageAsync(_db, _orgA, Repo, Digest));
        foreach (bool covered in new[] { false, true })
        {
            _coverage.Covered = covered;
            Assert.Equal(OciScanProjection.Project(null, covered).State, (await ReadAsync(_orgA)).Detail!.State);
        }

        await OciScanSeeder.ResultAsync(_db, _orgA, owner, "linux/amd64", [], [new SeedComponent("x", 0, [])]);
        var facts = (await _repo.GetFactsAsync(_orgA, [owner.Id]))[owner.Id];
        foreach (bool covered in new[] { false, true })
        {
            _coverage.Covered = covered;
            Assert.Equal(OciScanProjection.Project(facts, covered).State, (await ReadAsync(_orgA)).Detail!.State);
        }
    }

    [Fact]
    public void TheDigestCheck_RejectsATrailingNewline_ThatADollarAnchorWouldAdmit()
    {
        string valid = "sha256:" + new string('a', 64);

        Assert.True(OrgOciScanController.IsOciDigest(valid));
        Assert.False(OrgOciScanController.IsOciDigest(valid + "\n"));
        Assert.False(OrgOciScanController.IsOciDigest("sha256:" + new string('A', 64)));
        Assert.False(OrgOciScanController.IsOciDigest("sha512:" + new string('a', 64)));
        Assert.False(OrgOciScanController.IsOciDigest("sha256:" + new string('a', 63)));
    }

    [Fact]
    public async Task EachPlatform_CarriesWhenItsFindingsWereLastMatched()
    {
        var owner = OciScanOwner.Hosted(await OciScanSeeder.HostedImageAsync(_db, _orgA, Repo, Digest));
        await OciScanSeeder.ResultAsync(_db, _orgA, owner, "linux/amd64", [], [new SeedComponent("x", 0, [])]);
        await OciScanSeeder.ResultAsync(_db, _orgA, owner, "linux/arm64", [], [new SeedComponent("y", 0, [])]);
        const string rematched = "2026-06-20T08:00:00.000Z";
        await using (var conn = await _db.OpenAsync())
        {
            await Dapper.SqlMapper.ExecuteAsync(conn,
                "UPDATE oci_scan_coverage SET matched_at = @rematched WHERE org_id = @orgId AND platform = 'linux/arm64'",
                new { rematched, orgId = _orgA });
        }

        var platforms = (await ReadAsync(_orgA)).Detail!.Platforms;

        // Never re-matched: the match is the scan itself.
        Assert.Equal((OciScanSeeder.ScannedAt, OciScanSeeder.ScannedAt), (platforms[0].ScannedAt, platforms[0].MatchedAt));
        Assert.Equal((OciScanSeeder.ScannedAt, rematched), (platforms[1].ScannedAt, platforms[1].MatchedAt));
    }

    [Theory]
    [InlineData("pending", 3, "pending", 3)]
    [InlineData("failed", 5, "failed", 5)]
    [InlineData("done", 1, "none", null)]
    public void TheJobView_ExposesOnlyItsVocabulary(string stored, int attempts, string state, int? shownAttempts)
    {
        Assert.Equal(new OciScanJobView(state, shownAttempts), OciScanDetailReader.JobView((stored, attempts)));
        Assert.Equal(new OciScanJobView("none", null), OciScanDetailReader.JobView(null));
    }

    private sealed class FakeCoverage : IOciScanCoverage
    {
        public bool Enabled { get; set; } = true;

        public bool Covered { get; set; }

        public Task<bool> IsCoveredAsync(string orgId, CancellationToken ct = default) => Task.FromResult(Enabled && Covered);
    }
}
