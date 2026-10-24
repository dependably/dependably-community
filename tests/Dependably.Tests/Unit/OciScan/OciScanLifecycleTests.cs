using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.OciScan;
using Dependably.Infrastructure.Redis;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit.OciScan;

/// <summary>
/// How an OCI scan job's life ends and starts again, against the real schema: a parked job is
/// replaced once it is a rescan age old, a result stored with unverified advisories is queued
/// again whether or not the org's scanner claims rematch jobs, a claim never takes a job another
/// scanner has just deferred, and a replica that stops leading the sweep stops exporting its
/// last staleness readings.
/// </summary>
[Trait("Category", "Unit")]
public sealed class OciScanLifecycleTests : IAsyncLifetime
{
    private const string Now = "2026-06-15T12:00:00.000Z";
    private const string InFifteen = "2026-06-15T12:15:00.000Z";
    private const string DayAndAnHourAgo = "2026-06-14T11:00:00.000Z";
    private const string AnHourAgo = "2026-06-15T11:00:00.000Z";

    private readonly TestMetadataStore _db = new();
    private OciScanRepository _repo = null!;
    private string _org = null!;
    private string _package = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        _repo = new OciScanRepository(_db);
        _org = await OrgSeeder.InsertAsync(_db, "lifecycle-org");
        _package = await PackageSeeder.InsertAsync(_db, _org, "oci", "team/app");
        await _repo.TouchScannerAsync(_org, Now, "0.4.0", "remote", null);
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    // ── Parked jobs ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task Sweep_ReplacesAParkedScanJobOnceItIsARescanAgeOld_AndLeavesARecentOneParked()
    {
        var stale = await HostedAsync('1');
        var recent = await HostedAsync('2');
        string staleJob = await ParkedScanAsync(stale, '1', DayAndAnHourAgo);
        string recentJob = await ParkedScanAsync(recent, '2', AnHourAgo);

        await Sweep().RunPassAsync(default);

        var replaced = await JobAsync(stale);
        Assert.NotEqual(staleJob, replaced.Id);
        Assert.Equal(("scan", "pending", 0L), (replaced.Kind, replaced.State, replaced.Attempts));

        var kept = await JobAsync(recent);
        Assert.Equal((recentJob, "failed"), (kept.Id, kept.State));

        // The replacement is claimable; the parked image is no longer stuck.
        var claimed = Assert.Single(await _repo.ClaimAsync(_org, 4, 5, Now, InFifteen));
        Assert.Equal(replaced.Id, claimed.Id);
    }

    // ── Unverified advisories ───────────────────────────────────────────────────

    [Fact]
    public async Task Sweep_RequeuesAResultWithUnverifiedAdvisories_AsAScan_WithoutRematchOptIn()
    {
        var unverified = await HostedAsync('3');
        var clean = await HostedAsync('4');
        await DoneScanAsync(unverified, '3');
        await DoneScanAsync(clean, '4');
        await CoverageAsync(unverified, DayAndAnHourAgo, [UnverifiedGap]);
        await CoverageAsync(clean, DayAndAnHourAgo, []);
        Assert.False(await _repo.AcceptsRematchAsync(_org));

        Assert.Equal(1, await Sweep().RunPassAsync(default));

        var requeued = await JobAsync(unverified);
        Assert.Equal(("scan", "pending"), (requeued.Kind, requeued.State));
        Assert.Equal("done", (await JobAsync(clean)).State);
    }

    [Fact]
    public async Task Sweep_LeavesAFreshResultWithUnverifiedAdvisories_UntilItIsARescanAgeOld()
    {
        var owner = await HostedAsync('5');
        await DoneScanAsync(owner, '5');
        await CoverageAsync(owner, AnHourAgo, [UnverifiedGap]);

        Assert.Equal(0, await Sweep().RunPassAsync(default));
        Assert.Equal("done", (await JobAsync(owner)).State);
    }

    // ── Edge ────────────────────────────────────────────────────────────────────

    // An edge node hosts no scan API, so a job it queued would never drain.
    [Theory]
    [InlineData("edge", 0)]
    [InlineData("single", 1)]
    public async Task Enqueue_QueuesNothingOnAnEdgeNode(string mode, int expected)
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["DEPLOYMENT_MODE"] = mode,
        }).Build();
        var enqueuer = new OciScanEnqueuer(
            new OciScanOptions { Enabled = true }, _repo, TestTime.Frozen(), NullLogger<OciScanEnqueuer>.Instance,
            new EdgeMode(config));
        var owner = await HostedAsync('9');

        await enqueuer.EnqueueAsync(_org, owner, "team/app", Digest('9'));

        await using var conn = await _db.OpenAsync();
        Assert.Equal(expected, await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM oci_scan_jobs WHERE org_id = @org", new { org = _org }));
    }

    // ── Claim ───────────────────────────────────────────────────────────────────

    // Scanner B listed the job as a candidate before scanner A claimed and deferred it; B's
    // conditional update must not take it ahead of the deferral's next attempt.
    [Fact]
    public async Task Claim_DoesNotTakeAJobAnotherScannerHasJustDeferred_ButTakesOneThatIsDue()
    {
        var deferredOwner = await HostedAsync('6');
        var dueOwner = await HostedAsync('7');
        await _repo.EnqueueAsync(_org, deferredOwner, "team/app", Digest('6'), Now);
        await _repo.EnqueueAsync(_org, dueOwner, "team/app", Digest('7'), Now);
        var claimedByA = await _repo.ClaimAsync(_org, 2, 5, Now, InFifteen);
        Assert.Equal(2, claimedByA.Count);
        var deferred = claimedByA.Single(j => j.Owner == deferredOwner);
        var due = claimedByA.Single(j => j.Owner == dueOwner);
        Assert.True(await _repo.DeferAsync(_org, deferred.Id, deferred.Attempts, Now, InFifteen, "advisory source unreachable"));
        Assert.True(await _repo.DeferAsync(_org, due.Id, due.Attempts, Now, Now, "advisory source unreachable"));

        await using var conn = await _db.OpenAsync();
        Assert.False(await OciScanRepository.TryLeaseAsync(conn, _org, deferred.Id, Now, InFifteen));
        Assert.True(await OciScanRepository.TryLeaseAsync(conn, _org, due.Id, Now, InFifteen));
    }

    // ── Gauges ──────────────────────────────────────────────────────────────────

    // A replica that led one pass and then loses the leader lock stops reporting what that pass
    // saw: another replica now owns the readings, and a frozen value would read as current.
    [Fact]
    public async Task ATickSkippedForTheLeaderLock_ClearsTheReadingsTheLastLedPassReported()
    {
        var owner = await HostedAsync('8');
        await DoneScanAsync(owner, '8');
        await CoverageAsync(owner, DayAndAnHourAgo, []);
        await _repo.SetAcceptsRematchAsync(_org, true);
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO oci_tags (org_id, repository, tag, digest, pending_digest, pending_first_seen_at)
                VALUES (@org, 'team/app', 'latest', @accepted, @pending, @since)
                """,
                new { org = _org, accepted = Digest('a'), pending = Digest('b'), since = DayAndAnHourAgo });
        }

        var clock = new TimerSignallingClock(TestTime.KnownNow);
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["OCI_SCAN_SWEEP_SCHEDULE"] = "* * * * *",
        }).Build();
        var sweep = new OciScanSweepService(
            new OciScanOptions { Enabled = true }, _repo, config, new AirGapMode(config),
            NullLogger<OciScanSweepService>.Instance, clock, new GrantOnceLock(clock));

        using var stop = new CancellationTokenSource();
        await sweep.StartAsync(stop.Token);
        try
        {
            // Tick one: this replica leads and reports.
            clock.Advance(await NextTimerAsync(clock));
            var afterLed = await NextTimerAsync(clock);
            Assert.NotNull(sweep.LastOldestMatchAgeSeconds);
            Assert.NotNull(sweep.LastOldestPendingHoldAgeSeconds);

            // Tick two: another replica holds the lock.
            clock.Advance(afterLed);
            await NextTimerAsync(clock);
            Assert.Null(sweep.LastOldestMatchAgeSeconds);
            Assert.Null(sweep.LastOldestPendingHoldAgeSeconds);
        }
        finally
        {
            await stop.CancelAsync();
            await sweep.StopAsync(CancellationToken.None);
        }
    }

    // ── Helpers ─────────────────────────────────────────────────────────────────

    private const string UnverifiedGap =
        "advisories not recorded: 2 advisory id(s) not yet verified against the advisory source; the next match retries them";

    private static string Digest(char c) => "sha256:" + new string(c, 64);

    // The sweep loop's wait for the next minute of its every-minute schedule. A led tick also
    // arms its leader-lease renewal timer on the same clock, which is skipped here. The real-time
    // guard bounds a loop that never reaches its next wait; a healthy run is immediate.
    private static async Task<TimeSpan> NextTimerAsync(TimerSignallingClock clock)
    {
        while (true)
        {
            var due = await clock.NextTimerArmedAsync().WaitAsync(TimeSpan.FromSeconds(30));
            if (due == TimeSpan.FromMinutes(1))
            {
                return due;
            }
        }
    }

    private async Task<OciScanOwner> HostedAsync(char c)
        => OciScanOwner.Hosted(await PackageSeeder.InsertVersionAsync(_db, _package, Digest(c), "pkg:oci/app@" + c));

    private async Task<string> ParkedScanAsync(OciScanOwner owner, char c, string parkedAt)
    {
        await _repo.EnqueueAsync(_org, owner, "team/app", Digest(c), parkedAt);
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            UPDATE oci_scan_jobs SET state = 'failed', attempts = 5, updated_at = @parkedAt, completed_at = @parkedAt,
                last_error = 'registry unreachable'
            WHERE org_id = @org AND package_version_id = @pv
            """,
            new { org = _org, pv = owner.Id, parkedAt });
        return (await JobAsync(owner)).Id;
    }

    private async Task DoneScanAsync(OciScanOwner owner, char c)
    {
        await _repo.EnqueueAsync(_org, owner, "team/app", Digest(c), "2026-06-01T00:00:00.000Z");
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            UPDATE oci_scan_jobs SET state = 'done', updated_at = '2026-06-01T00:00:00.000Z'
            WHERE org_id = @org AND package_version_id = @pv
            """,
            new { org = _org, pv = owner.Id });
    }

    private async Task CoverageAsync(OciScanOwner owner, string matchedAt, IReadOnlyList<string> gaps)
    {
        string gapsJson = System.Text.Json.JsonSerializer.Serialize(gaps);
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO oci_scan_coverage (
                id, org_id, owner_kind, package_version_id, platform, scanner_version,
                extraction_version, osv_source, scanned_at, gaps_json, gap_count, content_gaps_json, matched_at)
            VALUES (@id, @org, 'package_version', @pv, 'linux/amd64', '0.4.0', '1', 'remote', @matchedAt,
                    @gapsJson, @gapCount, '[]', @matchedAt)
            """,
            new { id = Guid.NewGuid().ToString("N"), org = _org, pv = owner.Id, matchedAt, gapsJson, gapCount = gaps.Count });
    }

    private async Task<JobView> JobAsync(OciScanOwner owner)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.QuerySingleAsync<JobView>(
            """
            SELECT id AS Id, kind AS Kind, state AS State, attempts AS Attempts
            FROM oci_scan_jobs WHERE org_id = @org AND package_version_id = @pv AND kind = 'scan'
            """,
            new { org = _org, pv = owner.Id });
    }

    private sealed record JobView(string Id, string Kind, string State, long Attempts);

    private OciScanSweepService Sweep()
    {
        var config = new ConfigurationBuilder().Build();
        return new OciScanSweepService(
            new OciScanOptions { Enabled = true },
            _repo,
            config,
            new AirGapMode(config),
            NullLogger<OciScanSweepService>.Instance,
            TestTime.Frozen(),
            new InProcessDistributedLock(TimeProvider.System));
    }

    /// <summary>Grants the first acquisition, then reports the lock held elsewhere.</summary>
    private sealed class GrantOnceLock(TimeProvider time) : IDistributedLock
    {
        private readonly InProcessDistributedLock _inner = new(time);
        private int _acquisitions;

        public Task<ILockHandle?> TryAcquireAsync(string name, TimeSpan ttl, CancellationToken ct = default) =>
            Interlocked.Increment(ref _acquisitions) == 1
                ? _inner.TryAcquireAsync(name, ttl, ct)
                : Task.FromResult<ILockHandle?>(null);

        public Task<ILockHandle> AcquireAsync(
            string name, TimeSpan ttl, TimeSpan wait, TimeSpan retryInterval, CancellationToken ct = default) =>
            throw new NotSupportedException();
    }
}
