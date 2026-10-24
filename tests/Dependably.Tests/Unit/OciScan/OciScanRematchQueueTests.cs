using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.OciScan;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit.OciScan;

/// <summary>
/// The rematch half of the queue, against the real schema: which claims get rematch jobs, how a
/// finished job is replaced without reusing its attempt numbers, which images the sweep finds
/// due, and that an org whose scanner never opted in is left alone.
/// </summary>
[Trait("Category", "Unit")]
public sealed class OciScanRematchQueueTests : IAsyncLifetime
{
    private const string Now = "2026-06-15T12:00:00.000Z";
    private const string InFifteen = "2026-06-15T12:15:00.000Z";
    private const string DayAndAnHourAgo = "2026-06-14T11:00:00.000Z";
    private const string AnHourAgo = "2026-06-15T11:00:00.000Z";
    private const string Threshold = "2026-06-14T12:00:00.000Z";

    private readonly TestMetadataStore _db = new();
    private OciScanRepository _repo = null!;
    private string _org = null!;
    private string _other = null!;
    private string _package = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        _repo = new OciScanRepository(_db);
        _org = await OrgSeeder.InsertAsync(_db, "rematch-org");
        _other = await OrgSeeder.InsertAsync(_db, "rematch-other");
        _package = await PackageSeeder.InsertAsync(_db, _org, "oci", "team/app");
        await _repo.TouchScannerAsync(_org, Now, "0.4.0", "remote", null);
        await _repo.TouchScannerAsync(_other, Now, "0.4.0", "remote", null);
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    // ── Claim ───────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Claim_WithoutRematch_NeverHandsOutARematchJob()
    {
        var owner = await HostedAsync('1');
        await _repo.RequeueAsync(_org, owner, "team/app", Digest('1'), OciScanKinds.Rematch, Now);

        Assert.Empty(await _repo.ClaimAsync(_org, 4, 5, Now, InFifteen));

        var job = Assert.Single(await _repo.ClaimAsync(_org, 4, 5, Now, InFifteen, includeRematch: true));
        Assert.Equal(OciScanKinds.Rematch, job.Kind);
    }

    [Fact]
    public async Task Claim_HandsOutScansBeforeAnOlderRematch()
    {
        var rematched = await HostedAsync('1');
        var scanned = await HostedAsync('2');
        await _repo.RequeueAsync(_org, rematched, "team/app", Digest('1'), OciScanKinds.Rematch, DayAndAnHourAgo);
        await _repo.EnqueueAsync(_org, scanned, "team/app", Digest('2'), Now);

        var first = Assert.Single(await _repo.ClaimAsync(_org, 1, 5, Now, InFifteen, includeRematch: true));
        Assert.Equal(OciScanKinds.Scan, first.Kind);
        var second = Assert.Single(await _repo.ClaimAsync(_org, 1, 5, Now, InFifteen, includeRematch: true));
        Assert.Equal(OciScanKinds.Rematch, second.Kind);
    }

    [Fact]
    public async Task Claim_HoldsARematchBack_WhileTheSameImageHasAScanPending()
    {
        var owner = await HostedAsync('1');
        await _repo.RequeueAsync(_org, owner, "team/app", Digest('1'), OciScanKinds.Rematch, DayAndAnHourAgo);
        await _repo.EnqueueAsync(_org, owner, "team/app", Digest('1'), Now);

        var scan = Assert.Single(await _repo.ClaimAsync(_org, 4, 5, Now, InFifteen, includeRematch: true));
        Assert.Equal(OciScanKinds.Scan, scan.Kind);
        // The scan is leased but still pending, so the rematch stays held back.
        Assert.Empty(await _repo.ClaimAsync(_org, 4, 5, Now, InFifteen, includeRematch: true));
    }

    [Fact]
    public async Task AcceptsRematch_FollowsTheLatestClaim_AndNeverClaimedReadsOff()
    {
        Assert.False(await _repo.AcceptsRematchAsync(_org));
        await _repo.SetAcceptsRematchAsync(_org, true);
        Assert.True(await _repo.AcceptsRematchAsync(_org));
        Assert.False(await _repo.AcceptsRematchAsync(_other));
        await _repo.SetAcceptsRematchAsync(_org, false);
        Assert.False(await _repo.AcceptsRematchAsync(_org));
    }

    // ── Requeue ─────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Requeue_ReplacesAFinishedJobWithAFreshId_SoTheOldHoldersAttemptIsRefused()
    {
        var owner = await HostedAsync('1');
        await _repo.RequeueAsync(_org, owner, "team/app", Digest('1'), OciScanKinds.Rematch, DayAndAnHourAgo);
        var old = Assert.Single(await _repo.ClaimAsync(_org, 1, 5, DayAndAnHourAgo, "2026-06-14T11:15:00.000Z", true));
        await MarkAsync(old.Id, "failed");

        Assert.True(await _repo.RequeueAsync(_org, owner, "team/app", Digest('1'), OciScanKinds.Rematch, Now));
        var fresh = Assert.Single(await _repo.ClaimAsync(_org, 1, 5, Now, InFifteen, includeRematch: true));

        Assert.NotEqual(old.Id, fresh.Id);
        // Its own attempt budget starts again, on a row the old holder cannot name.
        Assert.Equal(1, fresh.Attempts);
        Assert.Equal(old.Attempts, fresh.Attempts);
        Assert.Null(await _repo.GetLeasedAsync(_org, old.Id, Now, old.Attempts));
        Assert.False(await _repo.FailAsync(_org, old.Id, old.Attempts, Now, park: true, null, "stale"));
        Assert.NotNull(await _repo.GetLeasedAsync(_org, fresh.Id, Now, fresh.Attempts));
    }

    [Fact]
    public async Task Requeue_NeverRemovesAPendingJob_AndASecondWriterQueuesNothing()
    {
        var owner = await HostedAsync('1');
        Assert.True(await _repo.RequeueAsync(_org, owner, "team/app", Digest('1'), OciScanKinds.Rematch, Now));
        var leased = Assert.Single(await _repo.ClaimAsync(_org, 1, 5, Now, InFifteen, includeRematch: true));

        // A second requeue while the first is leased: the leased job stays, nothing new is queued.
        Assert.False(await _repo.RequeueAsync(_org, owner, "team/app", Digest('1'), OciScanKinds.Rematch, Now));
        Assert.NotNull(await _repo.GetLeasedAsync(_org, leased.Id, Now, leased.Attempts));
        Assert.Equal(1, await CountAsync("SELECT COUNT(*) FROM oci_scan_jobs WHERE kind = 'rematch'"));
    }

    [Fact]
    public async Task Requeue_ConcurrentWriters_LeaveExactlyOnePendingJob()
    {
        var owner = await HostedAsync('1');
        await _repo.EnqueueAsync(_org, owner, "team/app", Digest('1'), DayAndAnHourAgo);
        var done = Assert.Single(await _repo.ClaimAsync(_org, 1, 5, DayAndAnHourAgo, "2026-06-14T11:15:00.000Z"));
        await MarkAsync(done.Id, "done");

        // The sweep's re-extraction, a scanner's escalation and a push enqueue, at once.
        bool[] results = await Task.WhenAll(
            _repo.RequeueAsync(_org, owner, "team/app", Digest('1'), OciScanKinds.Scan, Now),
            _repo.RequeueAsync(_org, owner, "team/app", Digest('1'), OciScanKinds.Scan, Now),
            _repo.EnqueueAsync(_org, owner, "team/app", Digest('1'), Now));

        Assert.Single(results, queued => queued);
        Assert.Equal(1, await CountAsync("SELECT COUNT(*) FROM oci_scan_jobs WHERE kind = 'scan' AND state = 'pending'"));
        Assert.Equal(1, await CountAsync("SELECT COUNT(*) FROM oci_scan_jobs"));
    }

    [Fact]
    public async Task Reextract_ClosesTheRematch_AndReplacesTheFinishedScan_OnlyForTheLiveAttempt()
    {
        var owner = await HostedAsync('1');
        await _repo.EnqueueAsync(_org, owner, "team/app", Digest('1'), DayAndAnHourAgo);
        var scan = Assert.Single(await _repo.ClaimAsync(_org, 1, 5, DayAndAnHourAgo, "2026-06-14T11:15:00.000Z"));
        await MarkAsync(scan.Id, "done");
        await _repo.RequeueAsync(_org, owner, "team/app", Digest('1'), OciScanKinds.Rematch, Now);
        var rematch = Assert.Single(await _repo.ClaimAsync(_org, 1, 5, Now, InFifteen, includeRematch: true));

        Assert.Equal((false, false), await _repo.ReextractAsync(rematch with { Attempts = rematch.Attempts + 1 }, Now));
        Assert.Equal((false, false), await _repo.ReextractAsync(rematch with { OrgId = _other }, Now));
        Assert.Equal((true, true), await _repo.ReextractAsync(rematch, Now));

        Assert.Equal("done", await ScalarAsync("SELECT state FROM oci_scan_jobs WHERE id = @id", new { id = rematch.Id }));
        string newScan = await ScalarAsync(
            "SELECT id FROM oci_scan_jobs WHERE kind = 'scan' AND state = 'pending'", new { });
        Assert.NotEqual(scan.Id, newScan);
    }

    [Fact]
    public async Task Reextract_RefusesAScanJob()
    {
        var owner = await HostedAsync('1');
        await _repo.EnqueueAsync(_org, owner, "team/app", Digest('1'), Now);
        var scan = Assert.Single(await _repo.ClaimAsync(_org, 1, 5, Now, InFifteen));
        Assert.Equal((false, false), await _repo.ReextractAsync(scan, Now));
        Assert.Equal("pending", await ScalarAsync("SELECT state FROM oci_scan_jobs WHERE id = @id", new { id = scan.Id }));
    }

    // ── Due images ──────────────────────────────────────────────────────────────

    [Fact]
    public async Task Due_OnlyImagesWhoseOldestMatchIsPastTheThreshold_OldestFirst()
    {
        var stale = await HostedAsync('1');
        var staler = await HostedAsync('2');
        var fresh = await HostedAsync('3');
        await CoverageAsync(_org, stale, "linux/amd64", matchedAt: DayAndAnHourAgo, contentGaps: "[]");
        // One fresh platform does not save an image whose other platform is stale.
        await CoverageAsync(_org, stale, "linux/arm64", matchedAt: AnHourAgo, contentGaps: "[]");
        await CoverageAsync(_org, staler, "linux/amd64", matchedAt: "2026-06-10T00:00:00.000Z", contentGaps: "[]");
        await CoverageAsync(_org, fresh, "linux/amd64", matchedAt: AnHourAgo, contentGaps: "[]");

        var due = await _repo.ListRematchDueAsync(_org, Threshold, 100);

        Assert.Equal([staler.Id, stale.Id], due.Select(d => d.Owner.Id));
        Assert.All(due, d => Assert.False(d.Legacy));
        Assert.Equal(Digest('2'), due[0].Digest);
        Assert.Equal("team/app", due[0].Repository);
        Assert.Single(await _repo.ListRematchDueAsync(_org, Threshold, 1));
    }

    [Fact]
    public async Task Due_ALegacyPlatformMarksTheImageForReextraction()
    {
        var owner = await HostedAsync('1');
        await CoverageAsync(_org, owner, "linux/amd64", matchedAt: DayAndAnHourAgo, contentGaps: "[]");
        await CoverageAsync(_org, owner, "linux/arm64", matchedAt: null, contentGaps: null, scannedAt: DayAndAnHourAgo);

        Assert.True(Assert.Single(await _repo.ListRematchDueAsync(_org, Threshold, 100)).Legacy);
    }

    [Fact]
    public async Task Due_SkipsAnImageWithAPendingJob_OrAJobFinishedWithinTheWindow()
    {
        var pending = await HostedAsync('1');
        var parked = await HostedAsync('2');
        var parkedLongAgo = await HostedAsync('3');
        foreach (var owner in new[] { pending, parked, parkedLongAgo })
        {
            await CoverageAsync(_org, owner, "linux/amd64", matchedAt: "2026-06-01T00:00:00.000Z", contentGaps: "[]");
        }

        await _repo.EnqueueAsync(_org, pending, "team/app", Digest('1'), "2026-06-01T00:00:00.000Z");
        await _repo.RequeueAsync(_org, parked, "team/app", Digest('2'), OciScanKinds.Rematch, AnHourAgo);
        await _repo.RequeueAsync(_org, parkedLongAgo, "team/app", Digest('3'), OciScanKinds.Rematch, DayAndAnHourAgo);
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync("UPDATE oci_scan_jobs SET state = 'failed' WHERE kind = 'rematch'");
        }

        Assert.Equal([parkedLongAgo.Id], (await _repo.ListRematchDueAsync(_org, Threshold, 100)).Select(d => d.Owner.Id));
    }

    [Fact]
    public async Task Due_IsScopedToTheOrg_AndAProxiedImageNeedsTheOrgsAccess()
    {
        var hosted = await HostedAsync('1');
        await CoverageAsync(_org, hosted, "linux/amd64", matchedAt: DayAndAnHourAgo, contentGaps: "[]");
        var held = await ProxiedAsync('4', grantTo: _org);
        var lost = await ProxiedAsync('5', grantTo: _other);
        await CoverageAsync(_org, held, "linux/amd64", matchedAt: DayAndAnHourAgo, contentGaps: "[]");
        // The org scanned this one once, then lost access to it.
        await CoverageAsync(_org, lost, "linux/amd64", matchedAt: DayAndAnHourAgo, contentGaps: "[]");

        var due = await _repo.ListRematchDueAsync(_org, Threshold, 100);
        Assert.Equal(
            new[] { hosted.Id, held.Id }.Order(StringComparer.Ordinal),
            due.Select(d => d.Owner.Id).Order(StringComparer.Ordinal));
        Assert.Equal(OciScanOwner.CacheArtifact, due.Single(d => d.Owner.Id == held.Id).Owner.Kind);
        Assert.Empty(await _repo.ListRematchDueAsync(_other, Threshold, 100));
        Assert.Equal(DayAndAnHourAgo, await _repo.GetOldestMatchAsync(_org));
        Assert.Null(await _repo.GetOldestMatchAsync(_other));
    }

    // ── Sweep ───────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Sweep_QueuesNothingForAnOrgThatNeverOptedIn()
    {
        var owner = await HostedAsync('1');
        await ScanDoneAsync(owner, '1');
        await CoverageAsync(_org, owner, "linux/amd64", matchedAt: DayAndAnHourAgo, contentGaps: null);

        Assert.Equal(0, await Sweep().RunPassAsync(default));
        await _repo.SetAcceptsRematchAsync(_org, false);
        Assert.Equal(0, await Sweep().RunPassAsync(default));
        Assert.Equal(0, await CountAsync("SELECT COUNT(*) FROM oci_scan_jobs WHERE state = 'pending'"));
    }

    [Fact]
    public async Task Sweep_QueuesOneRematchPerDueImage_AndARepeatQueuesNoDuplicate()
    {
        var owner = await HostedAsync('1');
        await ScanDoneAsync(owner, '1');
        await CoverageAsync(_org, owner, "linux/amd64", matchedAt: DayAndAnHourAgo, contentGaps: "[]");
        await _repo.SetAcceptsRematchAsync(_org, true);

        var sweep = Sweep();
        Assert.Equal(1, await sweep.RunPassAsync(default));
        Assert.Equal(0, await sweep.RunPassAsync(default));
        Assert.Equal(1, await CountAsync("SELECT COUNT(*) FROM oci_scan_jobs WHERE kind = 'rematch' AND state = 'pending'"));
        Assert.Equal(1, await CountAsync("SELECT COUNT(*) FROM oci_scan_jobs WHERE kind = 'scan' AND state = 'done'"));
    }

    [Fact]
    public async Task Sweep_ReextractsALegacyResult_InsteadOfReMatchingIt()
    {
        var owner = await HostedAsync('1');
        string scanJob = await ScanDoneAsync(owner, '1');
        await CoverageAsync(_org, owner, "linux/amd64", matchedAt: null, contentGaps: null, scannedAt: DayAndAnHourAgo);
        await _repo.SetAcceptsRematchAsync(_org, true);

        Assert.Equal(1, await Sweep().RunPassAsync(default));

        Assert.Equal(0, await CountAsync("SELECT COUNT(*) FROM oci_scan_jobs WHERE kind = 'rematch'"));
        string pending = await ScalarAsync("SELECT id FROM oci_scan_jobs WHERE kind = 'scan' AND state = 'pending'", new { });
        Assert.NotEqual(scanJob, pending);
    }

    [Fact]
    public async Task Sweep_UnderAirGap_StillQueuesRematches()
    {
        var owner = await HostedAsync('1');
        await ScanDoneAsync(owner, '1');
        await CoverageAsync(_org, owner, "linux/amd64", matchedAt: DayAndAnHourAgo, contentGaps: "[]");
        await _repo.SetAcceptsRematchAsync(_org, true);

        var sweep = Sweep(new Dictionary<string, string?> { ["AIR_GAPPED"] = "true" });
        Assert.Equal(1, await sweep.RunPassAsync(default));
    }

    [Fact]
    public async Task Sweep_ReportsTheOldestMatchOfOptedInOrgsOnly()
    {
        var owner = await HostedAsync('1');
        await ScanDoneAsync(owner, '1');
        await CoverageAsync(_org, owner, "linux/amd64", matchedAt: DayAndAnHourAgo, contentGaps: "[]");
        string otherPackage = await PackageSeeder.InsertAsync(_db, _other, "oci", "team/other");
        string otherVersion = await PackageSeeder.InsertVersionAsync(_db, otherPackage, Digest('9'), "pkg:oci/other");
        await CoverageAsync(_other, OciScanOwner.Hosted(otherVersion), "linux/amd64",
            matchedAt: "2026-01-01T00:00:00.000Z", contentGaps: "[]");
        await _repo.SetAcceptsRematchAsync(_org, true);

        var sweep = Sweep();
        await sweep.RunPassAsync(default);

        Assert.Equal(TimeSpan.FromHours(25).TotalSeconds, sweep.LastOldestMatchAgeSeconds);
    }

    [Fact]
    public async Task Sweep_ReportsTheOldestPendingTagHold_AndNothingWhenNoTagIsHolding()
    {
        var sweep = Sweep();
        await sweep.RunPassAsync(default);
        Assert.Null(sweep.LastOldestPendingHoldAgeSeconds);

        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO oci_tags (org_id, repository, tag, digest, pending_digest, pending_first_seen_at)
                VALUES (@org, 'team/app', 'latest', @accepted, @pending, @since)
                """,
                new { org = _org, accepted = Digest('a'), pending = Digest('b'), since = DayAndAnHourAgo });
        }

        await sweep.RunPassAsync(default);

        Assert.Equal(TimeSpan.FromHours(25).TotalSeconds, sweep.LastOldestPendingHoldAgeSeconds);
    }

    // ── Helpers ─────────────────────────────────────────────────────────────────

    private static string Digest(char c) => "sha256:" + new string(c, 64);

    private async Task<OciScanOwner> HostedAsync(char c)
        => OciScanOwner.Hosted(await PackageSeeder.InsertVersionAsync(_db, _package, Digest(c), "pkg:oci/app@" + c));

    private async Task<OciScanOwner> ProxiedAsync(char c, string grantTo)
    {
        string id = Guid.NewGuid().ToString("N");
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash)
            VALUES (@id, 'oci', 'library/nginx', @digest, 'manifest', @blobKey, @hash)
            """,
            new { id, digest = Digest(c), blobKey = "proxy/" + id, hash = new string(c, 64) });
        await conn.ExecuteAsync(
            "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES (@orgId, @id)",
            new { orgId = grantTo, id });
        return OciScanOwner.Proxied(id);
    }

    private async Task CoverageAsync(
        string orgId, OciScanOwner owner, string platform, string? matchedAt, string? contentGaps, string? scannedAt = null)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO oci_scan_coverage (
                id, org_id, owner_kind, package_version_id, cache_artifact_id, platform, scanner_version,
                extraction_version, osv_source, scanned_at, gaps_json, gap_count, content_gaps_json, matched_at)
            VALUES (@id, @orgId, @ownerKind, @pv, @ca, @platform, '0.4.0', '1', 'remote', @scannedAt, '[]', 0,
                    @contentGaps, @matchedAt)
            """,
            new
            {
                id = Guid.NewGuid().ToString("N"),
                orgId,
                ownerKind = owner.Kind,
                pv = owner.PackageVersionId,
                ca = owner.CacheArtifactId,
                platform,
                scannedAt = scannedAt ?? matchedAt,
                contentGaps,
                matchedAt,
            });
    }

    // The image's first scan, finished long ago.
    private async Task<string> ScanDoneAsync(OciScanOwner owner, char c)
    {
        await _repo.EnqueueAsync(_org, owner, "team/app", Digest(c), "2026-06-01T00:00:00.000Z");
        string id = await ScalarAsync("SELECT id FROM oci_scan_jobs WHERE kind = 'scan'", new { });
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE oci_scan_jobs SET state = 'done', updated_at = '2026-06-01T00:00:00.000Z' WHERE id = @id",
            new { id });
        return id;
    }

    private async Task MarkAsync(string jobId, string state)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE oci_scan_jobs SET state = @state, lease_expires_at = NULL WHERE id = @jobId",
            new { jobId, state });
    }

    private async Task<int> CountAsync(string sql)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.ExecuteScalarAsync<int>(sql);
    }

    private async Task<string> ScalarAsync(string sql, object args)
    {
        await using var conn = await _db.OpenAsync();
        return (await conn.ExecuteScalarAsync<string>(sql, args))!;
    }

    private OciScanSweepService Sweep(Dictionary<string, string?>? settings = null)
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(settings ?? []).Build();
        return new OciScanSweepService(
            new OciScanOptions { Enabled = true },
            _repo,
            config,
            new AirGapMode(config),
            NullLogger<OciScanSweepService>.Instance,
            TestTime.Frozen(),
            new Dependably.Infrastructure.Redis.InProcessDistributedLock(TimeProvider.System));
    }
}
