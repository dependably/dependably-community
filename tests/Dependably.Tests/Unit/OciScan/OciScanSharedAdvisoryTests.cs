using System.Collections.Concurrent;
using System.Text.Json;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.OciScan;
using Dependably.Infrastructure.Redis;
using Dependably.Infrastructure.Webhooks;
using Dependably.Protocol;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using NSubstitute;

namespace Dependably.Tests.Unit.OciScan;

/// <summary>
/// The <c>vulnerabilities</c> table is shared by every tenant and read by every tenant's gates,
/// lookups and KEV/EPSS joins, and a scanner result is posted with one tenant's credential. So
/// nothing in a result's advisory records is ever stored: an advisory the instance already holds
/// is linked as stored, one it does not is fetched by id from the registry's own advisory source,
/// and one that source does not know is dropped. Each case mixes a stored, a new and a fabricated
/// advisory in one result; both the scan-result and rematch paths are covered, and an unreachable
/// source refuses the result rather than falling back to the scanner's records.
/// </summary>
[Trait("Category", "Unit")]
public sealed class OciScanSharedAdvisoryTests : IAsyncLifetime
{
    private const string Digest = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
    private const string SharedId = "GHSA-q4x2-7c9m-wp3f";
    private const string SharedCve = "CVE-2026-31337";
    private const string NewId = "DSA-5990-1";
    private const string NewCve = "CVE-2026-40404";
    private const string FabricatedId = "GHSA-zz99-fake-0001";
    private const string KevCve = "CVE-2021-44228";
    private const string SecondNewId = "DSA-5991-1";

    private readonly TestMetadataStore _db = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen();
    private readonly FakeOsvSource _osv = new();
    private VulnerabilityRepository _vulns = null!;
    private OciScanRepository _repo = null!;
    private OciScanResultWriter _writer = null!;
    private string _attacker = null!;
    private string _victimVersion = null!;
    private string _imageVersion = null!;
    private string _sharedRowId = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        _repo = new OciScanRepository(_db);
        _vulns = new VulnerabilityRepository(_db, _clock);
        _writer = BuildWriter(new OciScanOptions());

        // OSV knows the new advisories, with their own values, and nothing about the fabricated one.
        _osv.Records[NewId] = OsvRecord(NewId, NewCve, "openssl buffer over-read");
        _osv.Records[SecondNewId] = OsvRecord(SecondNewId, "CVE-2026-40405", "openssl timing side channel");

        // CISA lists one CVE; the fabricated advisory will claim it.
        await _vulns.ReplaceKevCatalogAsync(new Dictionary<string, KevEntry>
        {
            [KevCve] = new KevEntry(true, "2021-12-10", "2021-12-24"),
        });

        // The victim org's npm package carries the advisory as the registry's OSV pass stored it.
        string victim = await OrgSeeder.InsertAsync(_db, "acme-payments");
        string victimPkg = await PackageSeeder.InsertAsync(_db, victim, "npm", "jsonwebtoken");
        _victimVersion = await PackageSeeder.InsertVersionAsync(_db, victimPkg, "8.5.1", "pkg:npm/jsonwebtoken@8.5.1");
        _sharedRowId = await _vulns.UpsertVulnerabilityAsync(new OsvAdvisory(
            SharedId, [SharedCve], "jsonwebtoken signature bypass", "CRITICAL", 9.8,
            [new OsvAffectedPackage("pkg:npm/jsonwebtoken", "npm", "jsonwebtoken", ["8.5.1"])],
            "2026-03-01T00:00:00Z", "2026-03-02T00:00:00Z", IsHydrated: true,
            RawJson: $$"""{"id":"{{SharedId}}","aliases":["{{SharedCve}}"]}"""), "npm", "jsonwebtoken");
        await _vulns.LinkVersionVulnAsync(_victimVersion, _sharedRowId);

        // The attacker org holds a scan:oci credential and an image of its own.
        _attacker = await OrgSeeder.InsertAsync(_db, "globex-builds");
        string imagePkg = await PackageSeeder.InsertAsync(_db, _attacker, "oci", "globex/api");
        _imageVersion = await PackageSeeder.InsertVersionAsync(_db, imagePkg, Digest, "pkg:oci/api@sha256%3A2222");

        _clock.Advance(TimeSpan.FromHours(3));
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    [Fact]
    public async Task AScanResult_StoresNothingFromItsRecords_AndLinksOnlyWhatTheInstanceCanVouchFor()
    {
        var before = await SharedRowAsync();

        var job = await ClaimScanAsync();
        var status = await _writer.WriteAsync(job, ScanBody([SharedId, NewId, FabricatedId]));

        Assert.Equal(OciScanResultOutcome.Stored, status.Outcome);
        await AssertSharedAdvisoryUntouchedAsync(before);
        await AssertNewAdvisoryIsTheSourcesRecordAsync();
        await AssertFabricatedAdvisoryAbsentAsync();
    }

    [Fact]
    public async Task ARematchResult_StoresNothingFromItsRecords_AndLinksOnlyWhatTheInstanceCanVouchFor()
    {
        // A first scan with no findings gives the image an inventory to rematch.
        Assert.Equal(OciScanResultOutcome.Stored, (await _writer.WriteAsync(await ClaimScanAsync(), ScanBody([]))).Outcome);
        _clock.Advance(TimeSpan.FromHours(25));
        var before = await SharedRowAsync();

        await _repo.RequeueAsync(
            _attacker, OciScanOwner.Hosted(_imageVersion), "globex/api", Digest, OciScanKinds.Rematch, Stamp());
        var job = Assert.Single(await _repo.ClaimAsync(_attacker, 1, 5, Stamp(), Later(), includeRematch: true));
        Assert.Equal(OciScanKinds.Rematch, job.Kind);
        var (status, summary) = await _writer.WriteMatchesAsync(job, await MatchBodyAsync([SharedId, NewId, FabricatedId]));

        Assert.Equal(OciScanResultOutcome.Stored, status.Outcome);
        Assert.Equal(2, summary!.Advisories);
        Assert.Equal(2, summary.Findings);
        await AssertSharedAdvisoryUntouchedAsync(before);
        await AssertNewAdvisoryIsTheSourcesRecordAsync();
        await AssertFabricatedAdvisoryAbsentAsync();
    }

    [Fact]
    public async Task AFabricatedAdvisoryAliasingAKevCve_IsNeverStored_SoAnotherOrgsKevReadIsUnchanged()
    {
        var kevBefore = await _vulns.GetKevEpssRowsByIdsAndAliasesAsync([SharedId, SharedCve]);
        Assert.False((await _vulns.GetGateSignalsAsync("package_version", _victimVersion)).HasKev);

        // The fabricated record claims the victim's CVE and a KEV-listed one.
        var body = ScanBody([FabricatedId]) with
        {
            Advisories = [Record(FabricatedId, aliases: [SharedCve, KevCve])],
        };
        Assert.Equal(OciScanResultOutcome.Stored, (await _writer.WriteAsync(await ClaimScanAsync(), body)).Outcome);

        // What any org's lookup reads for the victim's CVE: still only the victim's advisory, not KEV.
        var kevAfter = await _vulns.GetKevEpssRowsByIdsAndAliasesAsync([SharedId, SharedCve]);
        Assert.All(kevAfter, row => Assert.False(row.IsKev));
        Assert.Equal(kevBefore, kevAfter);
        Assert.Equal(0, await ScalarAsync<int>(
            "SELECT COUNT(*) FROM vulnerabilities WHERE osv_id = @osvId", new { osvId = FabricatedId }));
        Assert.Equal(0, await ScalarAsync<int>(
            "SELECT COUNT(*) FROM vulnerability_aliases WHERE osv_id = @osvId", new { osvId = FabricatedId }));
        Assert.False((await _vulns.GetGateSignalsAsync("package_version", _victimVersion)).HasKev);
        Assert.Empty(await QueryAsync<string>("SELECT vuln_id FROM oci_component_vulns"));
    }

    [Fact]
    public async Task AnUnreachableAdvisorySource_RefusesTheResult_AndStoresNothing()
    {
        _osv.Reachable = false;
        var before = await SharedRowAsync();
        var job = await ClaimScanAsync();

        var status = await _writer.WriteAsync(job, ScanBody([SharedId, NewId]));

        Assert.Equal(OciScanResultOutcome.AdvisorySourceUnavailable, status.Outcome);
        Assert.Equal(0, await ScalarAsync<int>(
            "SELECT COUNT(*) FROM vulnerabilities WHERE osv_id = @osvId", new { osvId = NewId }));
        Assert.Equal(before, await SharedRowAsync());
        Assert.Equal(0, await ScalarAsync<int>("SELECT COUNT(*) FROM oci_image_components", new { }));
        Assert.Empty(await QueryAsync<string>(
            "SELECT vuln_id FROM package_version_vulns WHERE package_version_id = @v", new { v = _imageVersion }));
        // The writer leaves the job to its caller, which returns it to the queue.
        Assert.Equal("pending", await ScalarAsync<string>("SELECT state FROM oci_scan_jobs WHERE id = @id", new { id = job.Id }));
    }

    [Fact]
    public async Task AnUnreachableAdvisorySource_IsNotConsulted_WhenEveryAdvisoryIsStored()
    {
        _osv.Reachable = false;

        var status = await _writer.WriteAsync(await ClaimScanAsync(), ScanBody([SharedId]));

        Assert.Equal(OciScanResultOutcome.Stored, status.Outcome);
        Assert.Equal(0, _osv.Lookups);
        Assert.Contains(_sharedRowId, await QueryAsync<string>(
            "SELECT vuln_id FROM package_version_vulns WHERE package_version_id = @v", new { v = _imageVersion }));
    }

    [Fact]
    public void ARecordNamingADifferentPackage_IsKeyedToThePackageTheSourceNames()
    {
        var advisory = _osv.Records[NewId];

        Assert.Equal(("Debian:12", "openssl"),
            OciScanAdvisoryResolver.StoredPackage(advisory, new OciScanAdvisoryRef(NewId, "npm", "jsonwebtoken")));
        // The same name in another ecosystem is another package.
        Assert.Equal(("Debian:12", "openssl"),
            OciScanAdvisoryResolver.StoredPackage(advisory, new OciScanAdvisoryRef(NewId, "npm", "openssl")));
        Assert.Equal(("debian:12", "OpenSSL"),
            OciScanAdvisoryResolver.StoredPackage(advisory, new OciScanAdvisoryRef(NewId, "debian:12", "OpenSSL")));
    }

    [Fact]
    public async Task AResultNamingOnlyUnknownAdvisories_ReadsPartial_NeverClean()
    {
        Assert.Equal(OciScanResultOutcome.Stored, (await _writer.WriteAsync(await ClaimScanAsync(), ScanBody([FabricatedId]))).Outcome);

        var facts = (await _repo.GetFactsAsync(_attacker, [_imageVersion]))[_imageVersion];
        Assert.Equal(0, facts.AdvisoryCount);
        Assert.Equal(1, facts.GapCount);
        Assert.Contains(await GapsAsync(), g => g.Contains("1 advisory id(s) the advisory source does not hold", StringComparison.Ordinal));
        Assert.Equal("partial", Dependably.Api.PackageVersionStatus.ComputeOciVersionStatus(
            new PackageVersion(), facts, covered: true, 10.0, "off"));
    }

    [Fact]
    public async Task AnIdInAnotherCase_ResolvesToTheSourcesRecord()
    {
        var status = await _writer.WriteAsync(await ClaimScanAsync(), ScanBody(["dsa-5990-1"]));

        Assert.Equal(OciScanResultOutcome.Stored, status.Outcome);
        string rowId = await ScalarAsync<string>(
            "SELECT id FROM vulnerabilities WHERE osv_id = @osvId", new { osvId = NewId });
        Assert.Contains(rowId, await LinksAsync());
        Assert.Empty(await GapsAsync());
    }

    [Fact]
    public async Task IdsPastTheFetchCap_AreAGap_AndTheResultIsStillStored()
    {
        var capped = BuildWriter(new OciScanOptions { AdvisoryFetchMax = 1 });

        var status = await capped.WriteAsync(await ClaimScanAsync(), ScanBody([SharedId, NewId, SecondNewId]));

        Assert.Equal(OciScanResultOutcome.Stored, status.Outcome);
        Assert.Equal(1, _osv.Lookups);
        // The stored advisory and one fetched; the other is a gap, not a finding.
        Assert.Equal(2, (await LinksAsync()).Count);
        Assert.Equal(1, await ScalarAsync<int>(
            "SELECT COUNT(*) FROM vulnerabilities WHERE osv_id IN ('DSA-5990-1', 'DSA-5991-1')", new { }));
        Assert.Contains(await GapsAsync(), g => g.Contains("1 advisory id(s) not yet verified", StringComparison.Ordinal));
    }

    [Fact]
    public async Task RecordsFetchedBeforeAnotherFails_AreKept_AndTheFailureIsAGap()
    {
        _osv.Unreachable.Add(SecondNewId);

        var status = await _writer.WriteAsync(await ClaimScanAsync(), ScanBody([NewId, SecondNewId]));

        // The source answered for one id, so this is not an outage: the result is stored, the
        // fetched record kept, and the id it could not answer for is a gap.
        Assert.Equal(OciScanResultOutcome.Stored, status.Outcome);
        Assert.Equal(1, await ScalarAsync<int>(
            "SELECT COUNT(*) FROM vulnerabilities WHERE osv_id = @osvId", new { osvId = NewId }));
        Assert.Equal(0, await ScalarAsync<int>(
            "SELECT COUNT(*) FROM vulnerabilities WHERE osv_id = @osvId", new { osvId = SecondNewId }));
        Assert.Contains(await GapsAsync(), g => g.Contains("1 advisory id(s) not yet verified", StringComparison.Ordinal));
    }

    [Fact]
    public async Task AnUnknownId_IsNotAskedAboutAgainWhileRemembered()
    {
        await _writer.WriteAsync(await ClaimScanAsync(), ScanBody([FabricatedId]));
        await RequeueScanAsync();
        await _writer.WriteAsync(await ClaimScanAsync(), ScanBody([FabricatedId]));
        Assert.Equal(1, _osv.Lookups);

        // Once forgotten, it is asked about again.
        _clock.Advance(OciScanAdvisoryResolver.UnknownTtl + TimeSpan.FromMinutes(1));
        await RequeueScanAsync();
        await _writer.WriteAsync(await ClaimScanAsync(), ScanBody([FabricatedId]));
        Assert.Equal(2, _osv.Lookups);
    }

    // The source answered one fetch before the budget ran out on the other: not an outage, so the
    // unfinished one is a gap.
    [Fact]
    public async Task FetchesStillRunningWhenTheTimeBudgetEnds_BesideAnAnsweredOne_AreAGap()
    {
        var options = new OciScanOptions();
        _osv.Hang = () => _clock.Advance(options.AdvisoryFetchBudget + TimeSpan.FromSeconds(1));
        _osv.HangIds.Add(NewId);

        var status = await _writer.WriteAsync(await ClaimScanAsync(), ScanBody([SharedId, SecondNewId, NewId]));

        Assert.Equal(OciScanResultOutcome.Stored, status.Outcome);
        Assert.Equal(0, await ScalarAsync<int>(
            "SELECT COUNT(*) FROM vulnerabilities WHERE osv_id = @osvId", new { osvId = NewId }));
        Assert.Equal(1, await ScalarAsync<int>(
            "SELECT COUNT(*) FROM vulnerabilities WHERE osv_id = @osvId", new { osvId = SecondNewId }));
        Assert.Contains(_sharedRowId, await LinksAsync());
        Assert.Contains(await GapsAsync(), g => g.Contains("1 advisory id(s) not yet verified", StringComparison.Ordinal));
    }

    // Under a short lease the fetch budget can end before the source's own client timeout would:
    // a source that hangs on every id has answered nothing, which is an outage, not a gap.
    [Fact]
    public async Task ASourceHangingOnEveryIdUnderAShortLease_IsAnOutage_AndDefersTheJob()
    {
        var options = new OciScanOptions { Lease = TimeSpan.FromSeconds(30) };
        var writer = BuildWriter(options);
        _osv.Hang = () => _clock.Advance(options.AdvisoryFetchBudget + TimeSpan.FromSeconds(1));

        var status = await writer.WriteAsync(await ClaimScanAsync(), ScanBody([SharedId, NewId]));

        Assert.Equal(OciScanResultOutcome.AdvisorySourceUnavailable, status.Outcome);
        Assert.Empty(await GapsAsync());
    }

    [Theory]
    [InlineData(60)]
    [InlineData(90)]
    [InlineData(900)]
    public void TheFetchBudget_OutlastsTheSourcesClientTimeout_WheneverTheLeaseLeavesRoom(int leaseSeconds)
    {
        var budget = new OciScanOptions { Lease = TimeSpan.FromSeconds(leaseSeconds) }.AdvisoryFetchBudget;

        Assert.True(budget > TimeSpan.FromSeconds(30), $"budget {budget} under a {leaseSeconds}s lease");
        Assert.True(budget < TimeSpan.FromSeconds(leaseSeconds));
    }

    [Fact]
    public async Task EveryFetchTimingOutInTheSource_IsAnOutage_AndDefersTheJob()
    {
        _osv.TimeOut = true;
        var job = await ClaimScanAsync();

        var status = await _writer.WriteAsync(job, ScanBody([NewId, SecondNewId]));

        Assert.Equal(OciScanResultOutcome.AdvisorySourceUnavailable, status.Outcome);
        Assert.Equal(0, await ScalarAsync<int>(
            "SELECT COUNT(*) FROM vulnerabilities WHERE osv_id = @osvId", new { osvId = NewId }));
        Assert.Empty(await GapsAsync());
    }

    [Fact]
    public async Task AFetchTimingOutInTheSource_BesideAnAnsweredOne_IsStillAGap()
    {
        _osv.Records[NewId] = OsvRecord(NewId, NewCve, "new");
        _osv.TimeOutIds.Add(SecondNewId);

        var status = await _writer.WriteAsync(await ClaimScanAsync(), ScanBody([NewId, SecondNewId]));

        Assert.Equal(OciScanResultOutcome.Stored, status.Outcome);
        Assert.Contains(await GapsAsync(), g => g.Contains("1 advisory id(s) not yet verified", StringComparison.Ordinal));
    }

    [Fact]
    public async Task AnOutageOutlastingTheDeferralWindow_StoresTheResultWithAGap()
    {
        _osv.Reachable = false;
        // First deferred a deferral window ago: an outage has held it back as long as it may.
        var first = await ClaimScanAsync();
        Assert.Equal(OciScanResultOutcome.AdvisorySourceUnavailable,
            (await _writer.WriteAsync(first, ScanBody([SharedId, NewId]))).Outcome);
        Assert.True(await _repo.DeferAsync(_attacker, first.Id, first.Attempts, Stamp(), Stamp(), "unreachable"));
        _clock.Advance(new OciScanOptions().RescanAge);
        var job = Assert.Single(await _repo.ClaimAsync(_attacker, 1, 5, Stamp(), Later()));

        var status = await _writer.WriteAsync(job, ScanBody([SharedId, NewId]));

        Assert.Equal(OciScanResultOutcome.Stored, status.Outcome);
        Assert.Contains(_sharedRowId, await LinksAsync());
        Assert.Equal(0, await ScalarAsync<int>(
            "SELECT COUNT(*) FROM vulnerabilities WHERE osv_id = @osvId", new { osvId = NewId }));
        Assert.Contains(await GapsAsync(), g => g.Contains("1 advisory id(s) not yet verified", StringComparison.Ordinal));
    }

    // The window runs from the first deferral, not from when the job was queued: an image that
    // waited longer than the window for its first claim is still deferred through an outage.
    [Fact]
    public async Task AJobQueuedLongBeforeItsFirstClaim_IsStillDeferredThroughAnOutage()
    {
        _osv.Reachable = false;
        await _repo.EnqueueAsync(_attacker, OciScanOwner.Hosted(_imageVersion), "globex/api", Digest, Stamp());
        _clock.Advance(new OciScanOptions().RescanAge + TimeSpan.FromHours(1));
        var job = Assert.Single(await _repo.ClaimAsync(_attacker, 1, 5, Stamp(), Later()));

        var status = await _writer.WriteAsync(job, ScanBody([SharedId, NewId]));

        Assert.Equal(OciScanResultOutcome.AdvisorySourceUnavailable, status.Outcome);
        Assert.Empty(await GapsAsync());
    }

    [Fact]
    public async Task AnOutageWithinTheWindowOfTheFirstDeferral_KeepsDeferring_AndALaterDeferralDoesNotMoveIt()
    {
        _osv.Reachable = false;
        var first = await ClaimScanAsync();
        Assert.Equal(OciScanResultOutcome.AdvisorySourceUnavailable,
            (await _writer.WriteAsync(first, ScanBody([SharedId, NewId]))).Outcome);
        Assert.True(await _repo.DeferAsync(_attacker, first.Id, first.Attempts, Stamp(), Stamp(), "unreachable"));
        _clock.Advance(new OciScanOptions().RescanAge - TimeSpan.FromHours(1));
        var second = Assert.Single(await _repo.ClaimAsync(_attacker, 1, 5, Stamp(), Later()));
        Assert.Equal(OciScanResultOutcome.AdvisorySourceUnavailable,
            (await _writer.WriteAsync(second, ScanBody([SharedId, NewId]))).Outcome);
        Assert.True(await _repo.DeferAsync(_attacker, second.Id, second.Attempts, Stamp(), Stamp(), "unreachable"));
        _clock.Advance(TimeSpan.FromHours(2));
        var third = Assert.Single(await _repo.ClaimAsync(_attacker, 1, 5, Stamp(), Later()));

        Assert.Equal(OciScanResultOutcome.Stored, (await _writer.WriteAsync(third, ScanBody([SharedId, NewId]))).Outcome);
    }

    // ── Activity ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task AGapOnlyResult_IsRecordedAsPartial_NeverClean()
    {
        Assert.Equal(OciScanResultOutcome.Stored,
            (await _writer.WriteAsync(await ClaimScanAsync(), ScanBody([FabricatedId]))).Outcome);

        string detail = Assert.Single(await ActivityAsync());
        Assert.DoesNotContain("clean", detail, StringComparison.Ordinal);
        Assert.Contains("1 coverage gap(s)", detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AResultWithNoAdvisoriesAndNoGaps_IsRecordedClean()
    {
        Assert.Equal(OciScanResultOutcome.Stored,
            (await _writer.WriteAsync(await ClaimScanAsync(), ScanBody([]))).Outcome);

        Assert.StartsWith("clean", Assert.Single(await ActivityAsync()), StringComparison.Ordinal);
    }

    // A daily rematch that finds what the last match found writes no activity row; one that
    // links a new advisory still does.
    [Fact]
    public async Task ARematchThatChangedNothing_WritesNoActivityRow_AndOneThatChangedSomethingDoes()
    {
        Assert.Equal(OciScanResultOutcome.Stored,
            (await _writer.WriteAsync(await ClaimScanAsync(), ScanBody([SharedId]))).Outcome);
        Assert.Single(await ActivityAsync());

        var unchanged = await ClaimRematchAsync();
        Assert.Equal(OciScanResultOutcome.Stored,
            (await _writer.WriteMatchesAsync(unchanged, await MatchBodyAsync([SharedId]))).Status.Outcome);
        Assert.Single(await ActivityAsync());

        var changed = await ClaimRematchAsync();
        Assert.Equal(OciScanResultOutcome.Stored,
            (await _writer.WriteMatchesAsync(changed, await MatchBodyAsync([SharedId, NewId]))).Status.Outcome);
        var rows = await ActivityAsync();
        Assert.Equal(2, rows.Count);
        Assert.Contains("1 new", rows[^1], StringComparison.Ordinal);
    }

    // ── Volume ──────────────────────────────────────────────────────────────────

    [Fact]
    public void AResultOverTheTotalFindingsCap_IsRefusedAsAWhole()
    {
        // Every component is inside the per-component cap; together they are over the total.
        var vulns = Enumerable.Range(0, 2_000)
            .Select(_ => new OciScanComponentVuln(SharedId, "unknown", null, null)).ToList();
        var components = Enumerable.Range(0, 126)
            .Select(i => new OciScanComponent(
                $"pkg:deb/debian/lib{i}@1", "Debian:12", $"lib{i}", "1", null, null, 0, "sha256:aa", null, 1, 0,
                null, null, vulns, null))
            .ToList();
        var body = new OciScanResultRequest(
            [new OciScanPlatformResult("linux/amd64", "0.4.0", "1", "remote", [], "native", true, components, [])],
            [Record(SharedId)], null);

        var (invalid, _) = OciScanResultWriter.Validate(body);

        Assert.NotNull(invalid);
        Assert.Equal(("findings", "error.ociScan.findingsMax"), (invalid!.Field, invalid.ErrorKey));
    }

    [Fact]
    public void AMatchOverTheTotalFindingsCap_IsRefusedAsAWhole()
    {
        var vulns = Enumerable.Repeat(SharedId, 2_000).ToList();
        var body = new OciScanMatchRequest(
            [new OciScanMatchPlatform("linux/amd64", "cov", "remote", "0.5.0", [],
                Enumerable.Range(0, 126).Select(i => new OciScanMatchFinding($"c{i}", vulns)).ToList())],
            [Record(SharedId)], null);

        var (invalid, _) = OciScanResultWriter.ValidateMatches(body);

        Assert.NotNull(invalid);
        Assert.Equal(("findings", "error.ociScan.findingsMax"), (invalid!.Field, invalid.ErrorKey));
    }

    // Components and findings go in as multi-row inserts, a bounded number of statements however
    // large the result, and land exactly as one row per component and per distinct finding.
    [Fact]
    public async Task ALargeResult_IsInsertedInBatches_AndWritesEveryRow()
    {
        const int componentCount = 1_200;
        var components = Enumerable.Range(0, componentCount)
            .Select(i => new OciScanComponent(
                $"pkg:npm/jsonwebtoken@1.{i}", "npm", "jsonwebtoken", $"1.{i}", i % 2 == 0 ? "src" : null, null,
                i % 7, "sha256:aa", i % 3 == 0 ? "RUN apt-get install" : null, i, 0,
                i % 2 == 0 ? true : null, null,
                // Two ids for every component, one of them twice: the duplicate is one finding.
                [new OciScanComponentVuln(SharedId, "reachable", null, "high"),
                 new OciScanComponentVuln(SharedId, "unknown", null, null),
                 new OciScanComponentVuln(NewId, "not_observed", "not in closure", "low")],
                new OciScanComponentVerdict("not_observed", "not in closure", "high")))
            .ToList();
        var body = new OciScanResultRequest(
            [new OciScanPlatformResult("linux/amd64", "0.4.0", "1", "remote", [], "native", true, components, [])],
            [Record(SharedId), Record(NewId)], null);
        var counting = new CountingStore(_db);
        var writer = new OciScanResultWriter(counting, BuildResolver(new OciScanOptions()), BuildScanService(_vulns), _clock);

        Assert.Equal(OciScanResultOutcome.Stored, (await writer.WriteAsync(await ClaimScanAsync(), body)).Outcome);

        Assert.InRange(counting.Statements.Count(sql => sql.Contains("INSERT INTO oci_image_components", StringComparison.Ordinal)), 1, 20);
        Assert.InRange(counting.Statements.Count(sql => sql.Contains("INSERT INTO oci_component_vulns", StringComparison.Ordinal)), 1, 20);

        var rows = await QueryAsync<ComponentView>(
            """
            SELECT name AS Name, version AS Version, source_name AS SourceName, layer_index AS LayerIndex,
                   layer_instruction AS Instruction, files_present AS FilesPresent,
                   in_entrypoint_closure AS InClosure, reachability_status AS Verdict
            FROM oci_image_components WHERE org_id = @org ORDER BY files_present
            """,
            new { org = _attacker });
        Assert.Equal(componentCount, rows.Count);
        for (int i = 0; i < componentCount; i++)
        {
            Assert.Equal(new ComponentView("jsonwebtoken", $"1.{i}", i % 2 == 0 ? "src" : null, i % 7,
                i % 3 == 0 ? "RUN apt-get install" : null, i, i % 2 == 0 ? 1 : null, "not_observed"), rows[i]);
        }

        var findings = await QueryAsync<FindingView>(
            """
            SELECT ic.version AS Version, v.osv_id AS OsvId, cv.reachability_status AS Reachability
            FROM oci_component_vulns cv
            JOIN oci_image_components ic ON ic.id = cv.component_id
            JOIN vulnerabilities v ON v.id = cv.vuln_id
            WHERE cv.org_id = @org
            """,
            new { org = _attacker });
        Assert.Equal(componentCount * 2, findings.Count);
        Assert.Equal(componentCount, findings.Count(f => f.OsvId == SharedId && f.Reachability == "reachable"));
        Assert.Equal(componentCount, findings.Count(f => f.OsvId == NewId && f.Reachability == "not_observed"));
        Assert.Equal(componentCount, findings.Select(f => f.Version).Distinct().Count());
    }

    private sealed record ComponentView(
        string Name, string Version, string? SourceName, long? LayerIndex, string? Instruction, long? FilesPresent,
        long? InClosure, string? Verdict);

    private sealed record FindingView(string Version, string OsvId, string Reachability);

    // ── Assertions ──────────────────────────────────────────────────────────────

    private async Task AssertSharedAdvisoryUntouchedAsync(SharedRow before)
    {
        var after = await SharedRowAsync();
        Assert.Equal(before, after);
        Assert.Equal("CRITICAL", after.Severity);
        Assert.Equal(9.8, after.CvssScore);

        // The alias index still answers the CVE with the advisory, and only with it.
        Assert.Equal([SharedCve], await QueryAsync<string>(
            "SELECT alias FROM vulnerability_aliases WHERE osv_id = @osvId", new { osvId = SharedId }));

        // The victim's gate still reads the registry's score.
        Assert.Equal(9.8, (await _vulns.GetGateSignalsAsync("package_version", _victimVersion)).MaxCvss);

        // The attacker's image finding is linked to the one stored row, not a duplicate.
        Assert.Equal(1, await ScalarAsync<int>(
            "SELECT COUNT(*) FROM vulnerabilities WHERE osv_id = @osvId", new { osvId = SharedId }));
        Assert.Contains(_sharedRowId, await LinksAsync());
        Assert.Contains(_sharedRowId, await FindingsAsync());
    }

    private async Task AssertNewAdvisoryIsTheSourcesRecordAsync()
    {
        await using var conn = await _db.OpenAsync();
        var row = await conn.QuerySingleAsync<NewRow>(
            """
            SELECT id AS Id, severity AS Severity, cvss_score AS Cvss, aliases AS Aliases, summary AS Summary,
                   ecosystem AS Ecosystem, package_name AS PackageName
            FROM vulnerabilities WHERE osv_id = @osvId
            """,
            new { osvId = NewId });

        // The source's values, none of the scanner's (LOW, 1.6, the decoy alias, "harmless").
        Assert.Equal(7.5, row.Cvss);
        Assert.Equal("HIGH", row.Severity);
        Assert.Equal("openssl buffer over-read", row.Summary);
        Assert.Equal(JsonSerializer.Serialize(new[] { NewCve }), row.Aliases);
        // Keyed to the package the source's record names, not the scanner's component.
        Assert.Equal(("Debian:12", "openssl"), (row.Ecosystem, row.PackageName));
        Assert.Equal([NewCve], await QueryAsync<string>(
            "SELECT alias FROM vulnerability_aliases WHERE osv_id = @osvId", new { osvId = NewId }));
        Assert.Contains(row.Id, await LinksAsync());
        Assert.Contains(row.Id, await FindingsAsync());
    }

    private async Task AssertFabricatedAdvisoryAbsentAsync()
    {
        Assert.Equal(0, await ScalarAsync<int>(
            "SELECT COUNT(*) FROM vulnerabilities WHERE osv_id = @osvId", new { osvId = FabricatedId }));
        Assert.Equal(0, await ScalarAsync<int>(
            "SELECT COUNT(*) FROM vulnerability_aliases WHERE alias = 'CVE-1999-0001'", new { }));
        Assert.Equal(2, (await LinksAsync()).Count);
        Assert.Equal(2, (await FindingsAsync()).Count);
        // The dropped id is a coverage gap, so the image never reads clean for it.
        Assert.Contains(await GapsAsync(), g => g.Contains("1 advisory id(s) the advisory source does not hold", StringComparison.Ordinal));
    }

    // ── Helpers ─────────────────────────────────────────────────────────────────

    private sealed record NewRow(
        string Id, string? Severity, double? Cvss, string? Aliases, string? Summary, string Ecosystem, string PackageName);

    private sealed record SharedRow(
        string Id, string? Severity, double? CvssScore, string? Aliases, string? Summary, string? OsvJson,
        string? ModifiedAt, string? FetchedAt, string? AffectedVersions);

    private async Task<SharedRow> SharedRowAsync()
    {
        await using var conn = await _db.OpenAsync();
        return await conn.QuerySingleAsync<SharedRow>(
            """
            SELECT id AS Id, severity AS Severity, cvss_score AS CvssScore, aliases AS Aliases,
                   summary AS Summary, osv_json AS OsvJson, modified_at AS ModifiedAt,
                   fetched_at AS FetchedAt, affected_versions AS AffectedVersions
            FROM vulnerabilities WHERE osv_id = @osvId
            """,
            new { osvId = SharedId });
    }

    private async Task<OciScanJob> ClaimScanAsync()
    {
        await _repo.EnqueueAsync(_attacker, OciScanOwner.Hosted(_imageVersion), "globex/api", Digest, Stamp());
        return Assert.Single(await _repo.ClaimAsync(_attacker, 1, 5, Stamp(), Later()));
    }

    private async Task<OciScanJob> ClaimRematchAsync()
    {
        _clock.Advance(TimeSpan.FromHours(25));
        await _repo.RequeueAsync(
            _attacker, OciScanOwner.Hosted(_imageVersion), "globex/api", Digest, OciScanKinds.Rematch, Stamp());
        return Assert.Single(await _repo.ClaimAsync(_attacker, 1, 5, Stamp(), Later(), includeRematch: true));
    }

    private Task<List<string>> ActivityAsync() => QueryAsync<string>(
        "SELECT detail FROM activity WHERE org_id = @org AND event_type = @type ORDER BY rowid",
        new { org = _attacker, type = OciScanResultWriter.ActivityType });

    private OciScanAdvisoryResolver BuildResolver(OciScanOptions options) =>
        new(_osv, _vulns, options, _clock, NullLogger<OciScanAdvisoryResolver>.Instance);

    private OciScanResultWriter BuildWriter(OciScanOptions options) =>
        new(_db, BuildResolver(options), BuildScanService(_vulns), _clock);

    private static OsvAdvisory OsvRecord(string id, string cve, string summary) =>
        OsvRecordParser.TryParse(JsonDocument.Parse($$"""
            {
              "id": "{{id}}",
              "aliases": ["{{cve}}"],
              "summary": "{{summary}}",
              "severity": [{ "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" }],
              "affected": [{ "package": { "ecosystem": "Debian:12", "name": "openssl" }, "versions": ["3.0.11-1~deb12u1"] }]
            }
            """).RootElement)!;

    private Task RequeueScanAsync() => _repo.RequeueAsync(
        _attacker, OciScanOwner.Hosted(_imageVersion), "globex/api", Digest, OciScanKinds.Scan, Stamp());

    private async Task<List<string>> GapsAsync() => (await QueryAsync<string>(
            "SELECT gaps_json FROM oci_scan_coverage WHERE org_id = @org", new { org = _attacker }))
        .SelectMany(json => JsonSerializer.Deserialize<List<string>>(json) ?? [])
        .ToList();

    private Task<List<string>> LinksAsync() => QueryAsync<string>(
        "SELECT vuln_id FROM package_version_vulns WHERE package_version_id = @v", new { v = _imageVersion });

    private Task<List<string>> FindingsAsync() => QueryAsync<string>(
        "SELECT vuln_id FROM oci_component_vulns WHERE org_id = @org", new { org = _attacker });

    private string Stamp() => _clock.GetUtcNow().ToUtcIsoMillis();

    private string Later() => _clock.GetUtcNow().AddMinutes(15).ToUtcIsoMillis();

    private static OciScanResultRequest ScanBody(IReadOnlyList<string> vulns) => new(
        [new OciScanPlatformResult(
            "linux/amd64", "0.4.0", "1", "remote", [], "native", true,
            [new OciScanComponent(
                "pkg:npm/jsonwebtoken@8.5.1", "npm", "jsonwebtoken", "8.5.1",
                null, null, 0, "sha256:aa", null, 4, 0, false, null,
                vulns.Select(v => new OciScanComponentVuln(v, "not_observed", "not in closure", "high")).ToList(),
                new OciScanComponentVerdict("not_observed", "not in closure", "high"))],
            [])],
        vulns.Select(v => Record(v)).ToList(),
        null);

    private async Task<OciScanMatchRequest> MatchBodyAsync(IReadOnlyList<string> vulns)
    {
        var owner = OciScanOwner.Hosted(_imageVersion);
        var platforms = await _repo.GetInventoryPlatformsAsync(_attacker, owner);
        var components = new List<OciInventoryComponent>();
        await foreach (var c in _repo.StreamInventoryComponentsAsync(_attacker, owner, OciScanLimits.MaxComponents))
        {
            components.Add(c);
        }

        return new OciScanMatchRequest(
            platforms.Select(p => new OciScanMatchPlatform(
                p.Platform, p.Id, "remote", "0.5.0", [],
                components.Where(c => c.Platform == p.Platform)
                    .Select(c => new OciScanMatchFinding(c.Id, vulns)).ToList())).ToList(),
            vulns.Select(v => Record(v)).ToList(),
            null);
    }

    // The record a hostile scanner posts: a minimal score, a LOW severity, and a decoy alias in
    // place of the real CVE, which would rewrite the stored aliases and the alias index.
    private static JsonElement Record(string id, IReadOnlyList<string>? aliases = null) => JsonDocument.Parse($$"""
        {
          "id": "{{id}}",
          "aliases": {{JsonSerializer.Serialize(aliases ?? ["CVE-1999-0001"])}},
          "summary": "harmless {{id}}",
          "severity": [{ "type": "CVSS_V3", "score": "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N" }],
          "database_specific": { "severity": "LOW" },
          "affected": [{ "package": { "ecosystem": "npm", "name": "jsonwebtoken" }, "versions": ["8.5.1"] }]
        }
        """).RootElement.Clone();

    private async Task<List<T>> QueryAsync<T>(string sql, object? args = null)
    {
        await using var conn = await _db.OpenAsync();
        return (await conn.QueryAsync<T>(sql, args)).AsList();
    }

    private async Task<T> ScalarAsync<T>(string sql, object args)
    {
        await using var conn = await _db.OpenAsync();
        return (await conn.ExecuteScalarAsync<T>(sql, args))!;
    }

    private VulnerabilityScanService BuildScanService(VulnerabilityRepository vulns)
    {
        var realOsv = new OsvClient(Substitute.For<IHttpClientFactory>(), NullLogger<OsvClient>.Instance);
        var config = new ConfigurationBuilder().Build();
        return new VulnerabilityScanService(new VulnerabilityScanService.Dependencies(
            _db, realOsv, vulns, new AuditRepository(_db), config,
                new AirGapMode(config),
            NullLogger<VulnerabilityScanService>.Instance,
            _clock,
            new OrgRepository(_db),
            new NullEventSink(), new InProcessDistributedLock(TimeProvider.System),
            new Dependably.Infrastructure.Alerts.AlertService(
                new Dependably.Infrastructure.Alerts.AlertRepository(_db, _clock),
                new Dependably.Infrastructure.Alerts.NoOpAlertNotifier(),
                NullLogger<Dependably.Infrastructure.Alerts.AlertService>.Instance),
            new SbomComponentScanner(realOsv, vulns, new SbomComponentVulnRepository(_db, _clock), NullLogger<SbomComponentScanner>.Instance),
            TestSbomPolicy.Service(_db, _clock),
            TestEnrichment.Unused(),
            TestEnrichment.NoConnection()));
    }

    /// <summary>The registry's advisory source: answers by id from <see cref="Records"/>.</summary>
    private sealed class FakeOsvSource : IOsvSource
    {
        private int _lookups;

        // Case-insensitive, as both real sources look ids up.
        public Dictionary<string, OsvAdvisory> Records { get; } = new(StringComparer.OrdinalIgnoreCase);

        public bool Reachable { get; set; } = true;

        // Ids the source cannot answer for while it answers for others.
        public HashSet<string> Unreachable { get; } = new(StringComparer.Ordinal);

        // When set, a lookup runs this (to move the clock) and then waits until it is cancelled.
        public Action? Hang { get; set; }

        // When non-empty, only these ids hang; the rest answer.
        public HashSet<string> HangIds { get; } = new(StringComparer.Ordinal);

        // A lookup the source's own HTTP timeout cancels: the caller's token is still live.
        public bool TimeOut { get; set; }

        public HashSet<string> TimeOutIds { get; } = new(StringComparer.Ordinal);

        public int Lookups => Volatile.Read(ref _lookups);

        public Task<List<OsvAdvisory>> QueryAsync(string purl, CancellationToken ct = default) =>
            Task.FromResult(new List<OsvAdvisory>());

        public Task<List<List<OsvAdvisory>>> QueryBatchAsync(IReadOnlyList<string> purls, CancellationToken ct = default) =>
            Task.FromResult(purls.Select(_ => new List<OsvAdvisory>()).ToList());

        public async Task<OsvIdLookupResult> TryGetAdvisoryAsync(string id, CancellationToken ct = default)
        {
            Interlocked.Increment(ref _lookups);
            if (TimeOut || TimeOutIds.Contains(id))
            {
                throw new TaskCanceledException("timeout", new TimeoutException());
            }

            if (Hang is { } hang && (HangIds.Count == 0 || HangIds.Contains(id)))
            {
                hang();
                // now-ok: waits only for the cancellation the fake clock advance above has fired.
                await Task.Delay(Timeout.InfiniteTimeSpan, ct);
            }

            return Reachable && !Unreachable.Contains(id)
                ? new OsvIdLookupResult(Records.GetValueOrDefault(id), Reached: true)
                : new OsvIdLookupResult(null, Reached: false);
        }
    }

    private sealed class NullEventSink : IPackageEventSink
    {
        private readonly ConcurrentQueue<PackageEventEnvelope> _seen = new();

        public void Dispatch(PackageEventEnvelope envelope) => _seen.Enqueue(envelope);
    }

    /// <summary>Opens every connection through a <see cref="CountingConnection"/> and keeps the statements.</summary>
    private sealed class CountingStore(IMetadataStore inner) : IMetadataStore
    {
        private readonly List<CountingConnection> _connections = [];

        public DbProvider Provider => inner.Provider;

        public IEnumerable<string> Statements => _connections.SelectMany(c => c.Statements);

        public async Task<System.Data.Common.DbConnection> OpenAsync(CancellationToken ct = default)
        {
            var connection = new CountingConnection(await inner.OpenAsync(ct));
            _connections.Add(connection);
            return connection;
        }
    }
}
