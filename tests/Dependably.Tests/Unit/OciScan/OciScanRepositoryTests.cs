using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.OciScan;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;

namespace Dependably.Tests.Unit.OciScan;

/// <summary>
/// The OCI scan queue's guarantees, against the real schema: one job per image per org, a lease
/// only one claim can hold, nothing visible across orgs, and a scanner that keeps crashing on an
/// image ending up parked rather than retried forever.
/// </summary>
[Trait("Category", "Unit")]
public sealed class OciScanRepositoryTests : IAsyncLifetime
{
    private const string Now = "2026-06-15T12:00:00.000Z";
    private const string InFifteen = "2026-06-15T12:15:00.000Z";
    private const string InTwenty = "2026-06-15T12:20:00.000Z";
    private const string Digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111";

    private readonly TestMetadataStore _db = new();
    private OciScanRepository _repo = null!;
    private string _orgA = null!;
    private string _orgB = null!;
    private string _versionA = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        _repo = new OciScanRepository(_db);
        _orgA = await OrgSeeder.InsertAsync(_db, "scan-a");
        _orgB = await OrgSeeder.InsertAsync(_db, "scan-b");
        string pkg = await PackageSeeder.InsertAsync(_db, _orgA, "oci", "team/app");
        _versionA = await PackageSeeder.InsertVersionAsync(_db, pkg, Digest, "pkg:oci/app@sha256%3A1111");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    [Fact]
    public async Task Enqueue_IsOncePerImageAndOrg()
    {
        var owner = OciScanOwner.Hosted(_versionA);
        Assert.True(await _repo.EnqueueAsync(_orgA, owner, "team/app", Digest, Now));
        Assert.False(await _repo.EnqueueAsync(_orgA, owner, "team/app", Digest, Now));

        await using var conn = await _db.OpenAsync();
        Assert.Equal(1, await conn.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM oci_scan_jobs"));
    }

    [Fact]
    public async Task Claim_LeasesAJobToOneCallerOnly()
    {
        await _repo.EnqueueAsync(_orgA, OciScanOwner.Hosted(_versionA), "team/app", Digest, Now);

        var first = await _repo.ClaimAsync(_orgA, 4, 5, Now, InFifteen);
        var second = await _repo.ClaimAsync(_orgA, 4, 5, Now, InFifteen);

        var job = Assert.Single(first);
        Assert.Equal(Digest, job.Digest);
        Assert.Equal(1, job.Attempts);
        Assert.Equal(InFifteen, job.LeaseExpiresAt);
        Assert.Empty(second);
        Assert.NotNull(await _repo.GetLeasedAsync(_orgA, job.Id, Now, job.Attempts));
    }

    [Fact]
    public async Task AnotherOrg_CannotClaimReadOrFailTheJob()
    {
        await _repo.EnqueueAsync(_orgA, OciScanOwner.Hosted(_versionA), "team/app", Digest, Now);

        Assert.Empty(await _repo.ClaimAsync(_orgB, 4, 5, Now, InFifteen));
        var job = Assert.Single(await _repo.ClaimAsync(_orgA, 4, 5, Now, InFifteen));
        Assert.Null(await _repo.GetLeasedAsync(_orgB, job.Id, Now, job.Attempts));
        Assert.Null(await _repo.GetLeasedForReadAsync(_orgB, job.Id, Now));
        Assert.False(await _repo.ExtendLeaseAsync(_orgB, job.Id, Now, InTwenty, job.Attempts));
        Assert.False(await _repo.FailAsync(_orgB, job.Id, job.Attempts, Now, park: true, null, "x"));
    }

    [Fact]
    public async Task ExpiredLease_IsClaimableAgain_AndParkedAfterTheLastAttempt()
    {
        await _repo.EnqueueAsync(_orgA, OciScanOwner.Hosted(_versionA), "team/app", Digest, Now);

        // Two attempts allowed. The scanner takes the job and vanishes each time.
        Assert.Single(await _repo.ClaimAsync(_orgA, 1, 2, Now, InFifteen));
        Assert.Single(await _repo.ClaimAsync(_orgA, 1, 2, InTwenty, "2026-06-15T12:35:00.000Z"));

        // The second lease lapses too: the job is parked, not handed out a third time.
        Assert.Empty(await _repo.ClaimAsync(_orgA, 1, 2, "2026-06-15T13:00:00.000Z", "2026-06-15T13:15:00.000Z"));
        await using var conn = await _db.OpenAsync();
        Assert.Equal("failed", await conn.ExecuteScalarAsync<string>("SELECT state FROM oci_scan_jobs"));
    }

    [Fact]
    public async Task RetryableFailure_WaitsForItsNextAttempt()
    {
        await _repo.EnqueueAsync(_orgA, OciScanOwner.Hosted(_versionA), "team/app", Digest, Now);
        var job = Assert.Single(await _repo.ClaimAsync(_orgA, 1, 5, Now, InFifteen));

        Assert.True(await _repo.FailAsync(_orgA, job.Id, job.Attempts, Now, park: false, nextAttemptAt: InTwenty, "OSV unreachable"));

        Assert.Empty(await _repo.ClaimAsync(_orgA, 1, 5, InFifteen, "2026-06-15T12:30:00.000Z"));
        var again = Assert.Single(await _repo.ClaimAsync(_orgA, 1, 5, InTwenty, "2026-06-15T12:35:00.000Z"));
        Assert.Equal(2, again.Attempts);
    }

    [Fact]
    public async Task FailAndExtend_RequireALiveLease()
    {
        await _repo.EnqueueAsync(_orgA, OciScanOwner.Hosted(_versionA), "team/app", Digest, Now);
        var job = Assert.Single(await _repo.ClaimAsync(_orgA, 1, 5, Now, InFifteen));

        Assert.False(await _repo.ExtendLeaseAsync(_orgA, job.Id, InTwenty, "2026-06-15T12:35:00.000Z", job.Attempts));
        Assert.False(await _repo.FailAsync(_orgA, job.Id, job.Attempts, InTwenty, park: true, null, "late"));
        Assert.Null(await _repo.GetLeasedAsync(_orgA, job.Id, InTwenty, job.Attempts));
        Assert.Null(await _repo.GetLeasedForReadAsync(_orgA, job.Id, InTwenty));
    }

    [Fact]
    public async Task ANegativeOrZeroAttempt_MatchesNoClaim_SoTheFenceHasNoBypass()
    {
        await _repo.EnqueueAsync(_orgA, OciScanOwner.Hosted(_versionA), "team/app", Digest, Now);
        var job = Assert.Single(await _repo.ClaimAsync(_orgA, 1, 5, Now, InFifteen));

        foreach (int attempt in new[] { -1, 0, int.MinValue })
        {
            Assert.Null(await _repo.GetLeasedAsync(_orgA, job.Id, Now, attempt));
            Assert.False(await _repo.ExtendLeaseAsync(_orgA, job.Id, Now, InTwenty, attempt));
        }

        // The image reads write nothing and are checked against the live lease alone.
        Assert.NotNull(await _repo.GetLeasedForReadAsync(_orgA, job.Id, Now));
        await using var conn = await _db.OpenAsync();
        Assert.Equal(InFifteen, await conn.ExecuteScalarAsync<string>("SELECT lease_expires_at FROM oci_scan_jobs"));
    }

    [Fact]
    public async Task ReclaimedJob_FencesTheFormerHolder_AndLeavesTheLiveClaimUntouched()
    {
        await _repo.EnqueueAsync(_orgA, OciScanOwner.Hosted(_versionA), "team/app", Digest, Now);
        var first = Assert.Single(await _repo.ClaimAsync(_orgA, 1, 5, Now, InFifteen));

        // The first lease lapses and a second claim takes the job.
        const string later = "2026-06-15T12:16:00.000Z";
        const string laterUntil = "2026-06-15T12:31:00.000Z";
        var second = Assert.Single(await _repo.ClaimAsync(_orgA, 1, 5, later, laterUntil));
        Assert.Equal(first.Id, second.Id);
        Assert.NotEqual(first.Attempts, second.Attempts);

        const string heartbeatAt = "2026-06-15T12:17:00.000Z";
        Assert.False(await _repo.ExtendLeaseAsync(
            _orgA, first.Id, heartbeatAt, "2026-06-15T12:40:00.000Z", first.Attempts));
        Assert.Null(await _repo.GetLeasedAsync(_orgA, first.Id, heartbeatAt, first.Attempts));
        Assert.False(await _repo.FailAsync(_orgA, first.Id, first.Attempts, heartbeatAt, park: true, null, "stale"));

        await using (var conn = await _db.OpenAsync())
        {
            var row = await conn.QuerySingleAsync<(string State, string Lease)>(
                "SELECT state AS State, lease_expires_at AS Lease FROM oci_scan_jobs");
            Assert.Equal(("pending", laterUntil), row);
        }

        Assert.NotNull(await _repo.GetLeasedAsync(_orgA, second.Id, heartbeatAt, second.Attempts));
        Assert.True(await _repo.ExtendLeaseAsync(
            _orgA, second.Id, heartbeatAt, "2026-06-15T12:40:00.000Z", second.Attempts));
        Assert.True(await _repo.FailAsync(
            _orgA, second.Id, second.Attempts, heartbeatAt, park: false, nextAttemptAt: InTwenty, "retry"));
    }

    [Fact]
    public async Task Facts_SumGapsAcrossPlatforms_AndAreScopedToTheOrg()
    {
        await using (var conn = await _db.OpenAsync())
        {
            foreach (var (platform, gaps) in new[] { ("linux/amd64", 2), ("linux/arm64", 1) })
            {
                await conn.ExecuteAsync(
                    """
                    INSERT INTO oci_scan_coverage (
                        id, org_id, owner_kind, package_version_id, platform, scanner_version,
                        extraction_version, osv_source, scanned_at, gaps_json, gap_count)
                    VALUES (@id, @orgId, 'package_version', @pv, @platform, '1', '1', 'remote', @now, '[]', @gaps)
                    """,
                    new { id = Guid.NewGuid().ToString("N"), orgId = _orgA, pv = _versionA, platform, now = Now, gaps });
            }
        }

        var facts = await _repo.GetFactsAsync(_orgA, [_versionA]);
        Assert.Equal(new OciScanFacts(3, 0, null, Now), facts[_versionA]);
        Assert.Empty(await _repo.GetFactsAsync(_orgB, [_versionA]));
    }

    [Fact]
    public async Task Scanner_HeartbeatKeepsReportedFieldsWhenACallOmitsThem()
    {
        await _repo.TouchScannerAsync(_orgA, Now, "0.3.0", "local", """{"Debian":true}""");
        await _repo.TouchScannerAsync(_orgA, InFifteen, null, null, null);

        Assert.Equal(InFifteen, await _repo.GetScannerLastSeenAsync(_orgA));
        Assert.Null(await _repo.GetScannerLastSeenAsync(_orgB));
        await using var conn = await _db.OpenAsync();
        Assert.Equal("0.3.0", await conn.ExecuteScalarAsync<string>(
            "SELECT scanner_version FROM oci_scanners WHERE org_id = @orgId", new { orgId = _orgA }));
    }

    [Fact]
    public async Task EnqueueMissing_QueuesCataloguedImagesWithoutAJob_Once()
    {
        Assert.Equal(1, await _repo.EnqueueMissingAsync(_orgA, Now, 100));
        Assert.Equal(0, await _repo.EnqueueMissingAsync(_orgA, Now, 100));
        Assert.Equal(0, await _repo.EnqueueMissingAsync(_orgB, Now, 100));
    }

    [Fact]
    public async Task CoverageBackfillListing_PagesByOwnerKey_SoUnfillableImagesDoNotStarveTheRest()
    {
        var owners = new List<string>();
        foreach (char c in "abc")
        {
            string digest = "sha256:" + new string(c, 64);
            string version = await OciScanSeeder.HostedImageAsync(_db, _orgA, "team/page", digest);
            await OciScanSeeder.ResultAsync(_db, _orgA, OciScanOwner.Hosted(version), "linux/amd64", [],
                [new SeedComponent("zlib", 0, [])]);
            owners.Add(version);
        }

        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync("UPDATE oci_scan_coverage SET manifest_digest = NULL");
        }

        // Nothing is ever filled, as for images whose manifest bytes are gone.
        var seen = new List<string>();
        string? after = null;
        for (int page = 0; page < 5; page++)
        {
            var rows = await _repo.ListCoverageMissingManifestDigestAsync(_orgA, 1, after);
            if (rows.Count == 0)
            {
                break;
            }

            seen.Add(rows[0].Owner.Id);
            after = rows[0].Owner.Id;
        }

        Assert.Equal(owners.Order(StringComparer.Ordinal).ToList(), seen);
    }

    [Fact]
    public async Task CoverageBackfill_RecordsAPlatformTheIndexDoesNotList_AsUnlistedNotNull()
    {
        string version = await OciScanSeeder.HostedImageAsync(_db, _orgA, "team/unlisted", "sha256:" + new string('d', 64));
        await OciScanSeeder.ResultAsync(_db, _orgA, OciScanOwner.Hosted(version), "linux/s390x", [],
            [new SeedComponent("zlib", 0, [])]);
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("UPDATE oci_scan_coverage SET manifest_digest = NULL");

        int filled = await _repo.FillCoverageManifestDigestsAsync(
            _orgA, OciScanOwner.Hosted(version),
            new OciPlatformMap("sha256:" + new string('d', 64), new Dictionary<string, string>()));

        Assert.Equal(1, filled);
        Assert.Equal(OciScanRepository.UnlistedPlatformDigest, await conn.ExecuteScalarAsync<string?>(
            "SELECT manifest_digest FROM oci_scan_coverage"));
        Assert.Contains(version,
            await _repo.GetOwnersNotCoveringAsync(_orgA, [version], "sha256:" + new string('e', 64)));
    }

    [Fact]
    public async Task AnUnreadableMapRow_NeverCovers_IsListedForRetry_AndIsRefilledWhenReadable()
    {
        string digest = "sha256:" + new string('f', 64);
        string version = await OciScanSeeder.HostedImageAsync(_db, _orgA, "team/unknown", digest);
        await OciScanSeeder.ResultAsync(_db, _orgA, OciScanOwner.Hosted(version), "linux/amd64", [],
            [new SeedComponent("zlib", 0, [])]);
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE oci_scan_coverage SET manifest_digest = @unknown", new { unknown = OciScanRepository.UnreadableMapDigest });

        Assert.Contains(version, await _repo.GetOwnersNotCoveringAsync(_orgA, [version], digest));
        Assert.Contains(await _repo.ListCoverageMissingManifestDigestAsync(_orgA, 10), r => r.Owner.Id == version);

        int filled = await _repo.FillCoverageManifestDigestsAsync(
            _orgA, OciScanOwner.Hosted(version),
            new OciPlatformMap(digest, new Dictionary<string, string> { ["linux/amd64"] = digest }));

        Assert.Equal(1, filled);
        Assert.Equal(digest, await conn.ExecuteScalarAsync<string?>("SELECT manifest_digest FROM oci_scan_coverage"));
        Assert.DoesNotContain(version, await _repo.GetOwnersNotCoveringAsync(_orgA, [version], digest));
    }

    [Fact]
    public async Task MarkingAnOwnerUnreadable_TurnsItsLegacyNullRowsNonCovering_AndLeavesFilledRowsAlone()
    {
        string digest = "sha256:" + new string('9', 64);
        string version = await OciScanSeeder.HostedImageAsync(_db, _orgA, "team/mark", digest);
        await OciScanSeeder.ResultAsync(_db, _orgA, OciScanOwner.Hosted(version), "linux/amd64", [],
            [new SeedComponent("zlib", 0, [])]);
        await OciScanSeeder.ResultAsync(_db, _orgA, OciScanOwner.Hosted(version), "linux/arm64", [],
            [new SeedComponent("zlib", 0, [])]);
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("UPDATE oci_scan_coverage SET manifest_digest = NULL");
        await conn.ExecuteAsync(
            "UPDATE oci_scan_coverage SET manifest_digest = @digest WHERE platform = 'linux/arm64'", new { digest });

        // A NULL row leaves membership to the reference graph: the owner reads as covering.
        Assert.DoesNotContain(version, await _repo.GetOwnersNotCoveringAsync(_orgA, [version], "sha256:" + new string('1', 64)));

        Assert.Equal(1, await _repo.MarkCoverageManifestUnreadableAsync(_orgA, OciScanOwner.Hosted(version)));
        Assert.Equal(0, await _repo.MarkCoverageManifestUnreadableAsync(_orgB, OciScanOwner.Hosted(version)));

        Assert.Equal(OciScanRepository.UnreadableMapDigest, await conn.ExecuteScalarAsync<string?>(
            "SELECT manifest_digest FROM oci_scan_coverage WHERE platform = 'linux/amd64'"));
        Assert.Equal(digest, await conn.ExecuteScalarAsync<string?>(
            "SELECT manifest_digest FROM oci_scan_coverage WHERE platform = 'linux/arm64'"));
        Assert.Contains(version, await _repo.GetOwnersNotCoveringAsync(_orgA, [version], "sha256:" + new string('1', 64)));
    }

    [Fact]
    public async Task DeletingTheVersion_RemovesItsScanRows()
    {
        await _repo.EnqueueAsync(_orgA, OciScanOwner.Hosted(_versionA), "team/app", Digest, Now);
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("DELETE FROM package_versions WHERE id = @id", new { id = _versionA });
        Assert.Equal(0, await conn.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM oci_scan_jobs"));
    }
}
