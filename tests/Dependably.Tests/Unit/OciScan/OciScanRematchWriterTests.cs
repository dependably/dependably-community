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
/// A rematch result against the real schema and the real vulnerability write path: it replaces
/// an image's findings and matching gaps without touching its inventory or content gaps, prunes
/// and announces image-level links the way a scan does, leaves alerts alone when an advisory
/// goes, and writes nothing at all for a stale attempt, a replaced inventory, or a body that names
/// a component the image does not hold.
/// </summary>
[Trait("Category", "Unit")]
public sealed class OciScanRematchWriterTests : IAsyncLifetime
{
    private const string Digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    private const string ContentGap = "platforms not scanned: linux/s390x";
    private const string MatchGap = "vulnerability matching: no OSV ecosystem for rhel 9";

    private readonly TestMetadataStore _db = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen();
    private readonly EventCapture _events = new();
    private OciScanRepository _repo = null!;
    private OciScanResultWriter _writer = null!;
    private string _org = null!;
    private string _other = null!;
    private string _version = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        _repo = new OciScanRepository(_db);
        var vulns = new VulnerabilityRepository(_db, _clock);
        // The advisory source knows every advisory these tests post, with the record they post.
        var osv = TestOsvSource.Create(byId: id => OsvRecordParser.TryParse(Record(id)));
        _writer = new OciScanResultWriter(
            _db, new OciScanAdvisoryResolver(osv, vulns, new OciScanOptions(), _clock, NullLogger<OciScanAdvisoryResolver>.Instance),
            BuildScanService(vulns), _clock);
        _org = await OrgSeeder.InsertAsync(_db, "rematch-writer");
        _other = await OrgSeeder.InsertAsync(_db, "rematch-writer-other");
        string pkg = await PackageSeeder.InsertAsync(_db, _org, "oci", "team/app");
        _version = await PackageSeeder.InsertVersionAsync(_db, pkg, Digest, "pkg:oci/app@sha256%3A1111");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    [Fact]
    public async Task ANewAdvisory_IsFoundLinkedAlertedAndAnnounced_AndOnlyItIsAnnounced()
    {
        await ScanAsync(["DSA-1"]);
        var (job, inventory) = await ClaimRematchAsync();

        var (status, summary) = await _writer.WriteMatchesAsync(job, Matches(inventory, ["DSA-1", "DSA-2"]));

        Assert.Equal(OciScanResultOutcome.Stored, status.Outcome);
        Assert.Equal(2, summary!.Advisories);
        Assert.Equal(["DSA-1", "DSA-2"], await FindingsAsync());
        Assert.Equal(["DSA-1", "DSA-2"], await LinksAsync());
        // A finding takes its component's stored verdict, not one the match result could supply.
        Assert.Equal(["not_observed"], await QueryAsync<string>(
            "SELECT DISTINCT reachability_status FROM oci_component_vulns"));
        // The alert dedup key is the stored advisory row's id, so this is the DSA-2 alert.
        Assert.Equal(1, await CountAsync(
            """
            SELECT COUNT(*) FROM alert a JOIN vulnerabilities v ON a.source_ref = v.id || ':oci:team/app'
            WHERE a.type = 'vuln_severity' AND v.osv_id = 'DSA-2'
            """));
        // The scan announced DSA-1; the rematch announces DSA-2 alone.
        Assert.Equal(2, _events.Vuln.Count);
        Assert.Contains("DSA-1", _events.Vuln[0]);
        Assert.Contains("DSA-2", _events.Vuln[1]);
        Assert.DoesNotContain("DSA-1", _events.Vuln[1]);
        Assert.Equal("done", await ScalarAsync<string>("SELECT state FROM oci_scan_jobs WHERE id = @id", new { id = job.Id }));
        Assert.Equal(_clock.GetUtcNow().ToUtcIsoMillis(), await ScalarAsync<string>(
            "SELECT matched_at FROM oci_scan_coverage", new { }));
    }

    [Fact]
    public async Task AnAdvisoryNoLongerFound_IsClearedFromFindingsAndLinks_ButItsAlertStays()
    {
        await ScanAsync(["DSA-1"]);
        Assert.Equal(1, await CountAsync("SELECT COUNT(*) FROM alert WHERE state = 'active'"));
        var (job, inventory) = await ClaimRematchAsync();

        var (status, _) = await _writer.WriteMatchesAsync(job, Matches(inventory, []));

        Assert.Equal(OciScanResultOutcome.Stored, status.Outcome);
        Assert.Empty(await FindingsAsync());
        Assert.Empty(await LinksAsync());
        Assert.Equal(1, await CountAsync("SELECT COUNT(*) FROM alert WHERE state = 'active'"));
        Assert.Single(_events.Vuln);
        var facts = await _repo.GetFactsAsync(_org, [_version]);
        Assert.Equal(0, facts[_version].AdvisoryCount);
    }

    [Fact]
    public async Task ContentGapsSurvive_AndMatchingGapsAreRecomputed()
    {
        await ScanAsync([], gaps: [ContentGap, MatchGap], contentGaps: [ContentGap]);
        var (job, inventory) = await ClaimRematchAsync();

        var (status, _) = await _writer.WriteMatchesAsync(job, Matches(inventory, [], matchGaps: []));

        Assert.Equal(OciScanResultOutcome.Stored, status.Outcome);
        Assert.Equal(JsonSerializer.Serialize(new[] { ContentGap }), await ScalarAsync<string>(
            "SELECT gaps_json FROM oci_scan_coverage", new { }));
        // Still partial: a rematch that dropped the content gap would have turned the image clean.
        Assert.Equal(1, (await _repo.GetFactsAsync(_org, [_version]))[_version].GapCount);
        Assert.Equal(JsonSerializer.Serialize(new[] { ContentGap }), await ScalarAsync<string>(
            "SELECT content_gaps_json FROM oci_scan_coverage", new { }));
    }

    [Fact]
    public async Task ASupersededAttempt_WritesNothing()
    {
        await ScanAsync(["DSA-1"]);
        var (stale, inventory) = await ClaimRematchAsync();
        _clock.Advance(TimeSpan.FromMinutes(16));
        var live = Assert.Single(await _repo.ClaimAsync(
            _org, 1, 5, _clock.GetUtcNow().ToUtcIsoMillis(), _clock.GetUtcNow().AddMinutes(15).ToUtcIsoMillis(), true));
        Assert.Equal(stale.Id, live.Id);

        var (status, _) = await _writer.WriteMatchesAsync(stale, Matches(inventory, ["DSA-1", "DSA-2"]));

        Assert.Equal(OciScanResultOutcome.LeaseLost, status.Outcome);
        Assert.Equal(["DSA-1"], await FindingsAsync());
        Assert.Equal(["DSA-1"], await LinksAsync());
        Assert.Equal("pending", await ScalarAsync<string>("SELECT state FROM oci_scan_jobs WHERE id = @id", new { id = live.Id }));
    }

    [Fact]
    public async Task AScanJob_CannotTakeAMatchResult()
    {
        await ScanAsync(["DSA-1"]);
        await RequeueScanAsync();
        var second = Assert.Single(await _repo.ClaimAsync(_org, 1, 5, Stamp(), Later()));
        var inventory = await InventoryAsync();

        var (status, _) = await _writer.WriteMatchesAsync(second, Matches(inventory, []));

        Assert.Equal(OciScanResultOutcome.LeaseLost, status.Outcome);
        Assert.Equal(["DSA-1"], await FindingsAsync());
    }

    [Fact]
    public async Task AReplacedInventory_IsRefused_AndTheJobStaysLeased()
    {
        await ScanAsync(["DSA-1"]);
        var (job, inventory) = await ClaimRematchAsync();
        // A re-extraction lands meanwhile: its coverage rows carry fresh ids.
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync("UPDATE oci_scan_coverage SET id = 'replaced-by-reextraction'");
        }

        var (status, _) = await _writer.WriteMatchesAsync(job, Matches(inventory, ["DSA-1", "DSA-2"]));

        Assert.Equal(OciScanResultOutcome.InventoryChanged, status.Outcome);
        Assert.Equal(["DSA-1"], await FindingsAsync());
        Assert.NotNull(await _repo.GetLeasedAsync(_org, job.Id, Stamp(), job.Attempts));
    }

    [Fact]
    public async Task AReextractionAfterTheInventoryRead_IsAConflict_NotAMalformedBody()
    {
        await ScanAsync(["DSA-1"]);
        var (job, inventory) = await ClaimRematchAsync();
        // A real re-extraction lands between the scanner's inventory read and its matches post:
        // new coverage rows and new component ids.
        await RequeueScanAsync();
        var rescan = Assert.Single(await _repo.ClaimAsync(_org, 1, 5, Stamp(), Later()));
        Assert.Equal(OciScanKinds.Scan, rescan.Kind);
        Assert.Equal(OciScanResultOutcome.Stored, (await PostScanAsync(rescan, ["DSA-3"], [], [])).Outcome);

        var (status, _) = await _writer.WriteMatchesAsync(job, Matches(inventory, ["DSA-1", "DSA-2"]));

        Assert.Equal(OciScanResultOutcome.InventoryChanged, status.Outcome);
        Assert.Equal(["DSA-3"], await FindingsAsync());
        Assert.Equal(0, await CountAsync("SELECT COUNT(*) FROM vulnerabilities WHERE osv_id = 'DSA-2'"));
        Assert.NotNull(await _repo.GetLeasedAsync(_org, job.Id, Stamp(), job.Attempts));
    }

    [Fact]
    public async Task OnePlatformStale_OneCurrent_WritesNeitherPlatform()
    {
        await ScanAsync(["DSA-1"], platforms: ["linux/amd64", "linux/arm64"]);
        var (job, inventory) = await ClaimRematchAsync();
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync("UPDATE oci_scan_coverage SET id = 'replaced' WHERE platform = 'linux/arm64'");
        }

        var (status, _) = await _writer.WriteMatchesAsync(job, Matches(inventory, ["DSA-1", "DSA-2"]));

        Assert.Equal(OciScanResultOutcome.InventoryChanged, status.Outcome);
        Assert.Equal(["DSA-1", "DSA-1"], await FindingsAsync());
        Assert.Equal(0, await CountAsync("SELECT COUNT(*) FROM oci_scan_coverage WHERE matched_at <> scanned_at"));
    }

    [Fact]
    public async Task LeavingOutAStoredPlatform_IsInvalid()
    {
        await ScanAsync(["DSA-1"], platforms: ["linux/amd64", "linux/arm64"]);
        var (job, inventory) = await ClaimRematchAsync();

        var body = Matches(inventory, []);
        var (status, _) = await _writer.WriteMatchesAsync(job, body with { Platforms = [body.Platforms![0]] });

        Assert.Equal(OciScanResultOutcome.Invalid, status.Outcome);
        Assert.Equal("error.ociScan.platformsIncomplete", status.ErrorKey);
        Assert.Equal(["DSA-1", "DSA-1"], await FindingsAsync());
    }

    [Fact]
    public async Task AComponentTheImageDoesNotHold_IsInvalid()
    {
        await ScanAsync(["DSA-1"]);
        var (job, inventory) = await ClaimRematchAsync();
        // Another org's component of an image it scanned itself.
        string otherPkg = await PackageSeeder.InsertAsync(_db, _other, "oci", "team/app");
        string otherVersion = await PackageSeeder.InsertVersionAsync(_db, otherPkg, Digest, "pkg:oci/app@sha256%3A1111");
        string foreign = Guid.NewGuid().ToString("N");
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO oci_image_components (id, org_id, owner_kind, package_version_id, platform, purl, ecosystem, name, version)
                VALUES (@foreign, @other, 'package_version', @otherVersion, 'linux/amd64', 'pkg:deb/debian/zlib1g@1', 'deb', 'zlib1g', '1')
                """,
                new { foreign, other = _other, otherVersion });
        }

        var body = Matches(inventory, ["DSA-2"]);
        var platform = body.Platforms![0];
        body = body with { Platforms = [platform with { Findings = [new OciScanMatchFinding(foreign, ["DSA-2"])] }] };
        var (status, _) = await _writer.WriteMatchesAsync(job, body);

        Assert.Equal(OciScanResultOutcome.Invalid, status.Outcome);
        Assert.Equal("error.ociScan.findingUnknown", status.ErrorKey);
        Assert.Equal(["DSA-1"], await FindingsAsync());
        Assert.Equal("pending", await ScalarAsync<string>("SELECT state FROM oci_scan_jobs WHERE id = @id", new { id = job.Id }));
    }

    [Fact]
    public async Task AProxiedImage_GetsFindingsButNoSharedRowWrites()
    {
        string ca = Guid.NewGuid().ToString("N");
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash)
                VALUES (@ca, 'oci', 'library/nginx', @digest, 'manifest', 'proxy/abc', 'abc')
                """,
                new { ca, digest = Digest });
            await conn.ExecuteAsync(
                "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES (@org, @ca)", new { org = _org, ca });
        }

        var owner = OciScanOwner.Proxied(ca);
        await _repo.EnqueueAsync(_org, owner, "library/nginx", Digest, Stamp());
        var scan = Assert.Single(await _repo.ClaimAsync(_org, 1, 5, Stamp(), Later()));
        await PostScanAsync(scan, ["DSA-1"], [], []);
        await _repo.RequeueAsync(_org, owner, "library/nginx", Digest, OciScanKinds.Rematch, Stamp());
        var job = Assert.Single(await _repo.ClaimAsync(_org, 1, 5, Stamp(), Later(), true));
        var inventory = await InventoryAsync(owner);

        var (status, _) = await _writer.WriteMatchesAsync(job, Matches(inventory, ["DSA-1", "DSA-2"]));

        Assert.Equal(OciScanResultOutcome.Stored, status.Outcome);
        Assert.Equal(2, await CountAsync("SELECT COUNT(*) FROM oci_component_vulns"));
        Assert.Equal(0, await CountAsync("SELECT COUNT(*) FROM package_version_vulns"));
        Assert.Empty(_events.Vuln);
    }

    [Fact]
    public async Task AFullResultOnARematchJob_IsTakenAsAReextraction()
    {
        await ScanAsync(["DSA-1"]);
        var (job, _) = await ClaimRematchAsync();

        var status = await PostScanAsync(job, ["DSA-2"], [], []);

        Assert.Equal(OciScanResultOutcome.Stored, status.Outcome);
        Assert.Equal(["DSA-2"], await FindingsAsync());
        Assert.Equal("done", await ScalarAsync<string>("SELECT state FROM oci_scan_jobs WHERE id = @id", new { id = job.Id }));
    }

    [Fact]
    public async Task AReextraction_PrunesUnsupportedLinks_AndAnnouncesOnlyNewOnes()
    {
        await ScanAsync(["DSA-1", "DSA-2"]);
        await RequeueScanAsync();
        var second = Assert.Single(await _repo.ClaimAsync(_org, 1, 5, Stamp(), Later()));

        await PostScanAsync(second, ["DSA-2", "DSA-3"], [], []);

        Assert.Equal(["DSA-2", "DSA-3"], await LinksAsync());
        Assert.Equal(2, _events.Vuln.Count);
        Assert.Contains("DSA-3", _events.Vuln[1]);
        Assert.DoesNotContain("DSA-2", _events.Vuln[1]);
        Assert.Contains(await QueryAsync<string>("SELECT detail FROM activity WHERE event_type = 'oci_scan'"),
            d => d.Contains("1 new, 1 cleared", StringComparison.Ordinal));
    }

    [Fact]
    public async Task TheInventoryStream_ServesEveryStoredComponentOfTheImage_InPlatformOrder()
    {
        await ScanAsync(["DSA-1"], platforms: ["linux/arm64", "linux/amd64"]);

        var platforms = await _repo.GetInventoryPlatformsAsync(_org, OciScanOwner.Hosted(_version));
        var components = new List<OciInventoryComponent>();
        await foreach (var c in _repo.StreamInventoryComponentsAsync(_org, OciScanOwner.Hosted(_version), 100))
        {
            components.Add(c);
        }

        Assert.Equal(["linux/amd64", "linux/arm64"], platforms.Select(p => p.Platform));
        Assert.Equal(["linux/amd64", "linux/arm64"], components.Select(c => c.Platform));
        Assert.Empty(await _repo.GetInventoryPlatformsAsync(_other, OciScanOwner.Hosted(_version)));
        await foreach (var _ in _repo.StreamInventoryComponentsAsync(_other, OciScanOwner.Hosted(_version), 100))
        {
            Assert.Fail("another org's stream must be empty");
        }
    }

    [Fact]
    public async Task AFreshResult_WhoseManifestCouldNotBeRead_RecordsANonCoveringSentinel_NotNull()
    {
        var vulns = new VulnerabilityRepository(_db, _clock);
        var reader = new OciPlatformManifestReader(
            _db, new Dependably.Storage.TieredBlobStorage(new Dependably.Storage.InMemoryBlobStore(), new Dependably.Storage.InMemoryBlobStore()),
            NullLogger<OciPlatformManifestReader>.Instance);
        var osv = TestOsvSource.Create(byId: id => OsvRecordParser.TryParse(Record(id)));
        _writer = new OciScanResultWriter(
            _db, new OciScanAdvisoryResolver(osv, vulns, new OciScanOptions(), _clock, NullLogger<OciScanAdvisoryResolver>.Instance),
            BuildScanService(vulns), _clock, reader);

        // No oci_blobs row for the image: the map cannot be read.
        await ScanAsync(["DSA-1"]);

        Assert.Equal(OciScanRepository.UnreadableMapDigest, await ScalarAsync<string>(
            "SELECT manifest_digest FROM oci_scan_coverage", new { }));
        Assert.Contains(_version, await _repo.GetOwnersNotCoveringAsync(_org, [_version], "sha256:" + new string('1', 64)));
    }

    [Fact]
    public async Task AFreshResult_WithNoReaderWired_LeavesManifestDigestNull()
    {
        await ScanAsync(["DSA-1"]);

        Assert.Null(await ScalarOrNullAsync("SELECT manifest_digest FROM oci_scan_coverage"));
    }

    private async Task<string?> ScalarOrNullAsync(string sql)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.ExecuteScalarAsync<string?>(sql);
    }

    // ── Helpers ─────────────────────────────────────────────────────────────────

    private string Stamp() => _clock.GetUtcNow().ToUtcIsoMillis();

    private string Later() => _clock.GetUtcNow().AddMinutes(15).ToUtcIsoMillis();

    private async Task ScanAsync(
        IReadOnlyList<string> vulns, IReadOnlyList<string>? gaps = null, IReadOnlyList<string>? contentGaps = null,
        IReadOnlyList<string>? platforms = null)
    {
        await _repo.EnqueueAsync(_org, OciScanOwner.Hosted(_version), "team/app", Digest, Stamp());
        var job = Assert.Single(await _repo.ClaimAsync(_org, 1, 5, Stamp(), Later()));
        var status = await PostScanAsync(job, vulns, gaps ?? [], contentGaps ?? [], platforms);
        Assert.Equal(OciScanResultOutcome.Stored, status.Outcome);
        _clock.Advance(TimeSpan.FromHours(25));
    }

    private async Task<OciScanResultStatus> PostScanAsync(
        OciScanJob job, IReadOnlyList<string> vulns, IReadOnlyList<string> gaps, IReadOnlyList<string>? contentGaps,
        IReadOnlyList<string>? platforms = null)
    {
        var body = new OciScanResultRequest(
            (platforms ?? ["linux/amd64"]).Select(p => new OciScanPlatformResult(
                p, "0.4.0", "1", "remote", gaps, "native", true,
                [new OciScanComponent(
                    "pkg:deb/debian/libssl3@3.0.11-1~deb12u1?distro=debian-12", "deb", "libssl3", "3.0.11-1~deb12u1",
                    "openssl", "3.0.11-1~deb12u1", 0, "sha256:aa", null, 4, 0, false, null,
                    vulns.Select(v => new OciScanComponentVuln(v, "not_observed", "not in closure", "high")).ToList(),
                    new OciScanComponentVerdict("not_observed", "not in closure", "high"))],
                contentGaps)).ToList(),
            vulns.Select(Record).ToList(),
            null);
        return await _writer.WriteAsync(job, body);
    }

    private async Task RequeueScanAsync()
        => await _repo.RequeueAsync(_org, OciScanOwner.Hosted(_version), "team/app", Digest, OciScanKinds.Scan, Stamp());

    private async Task<(OciScanJob Job, IReadOnlyList<(OciInventoryPlatform Platform, List<OciInventoryComponent> Components)> Inventory)>
        ClaimRematchAsync()
    {
        await _repo.RequeueAsync(_org, OciScanOwner.Hosted(_version), "team/app", Digest, OciScanKinds.Rematch, Stamp());
        var job = Assert.Single(await _repo.ClaimAsync(_org, 1, 5, Stamp(), Later(), includeRematch: true));
        Assert.Equal(OciScanKinds.Rematch, job.Kind);
        return (job, await InventoryAsync());
    }

    private async Task<IReadOnlyList<(OciInventoryPlatform Platform, List<OciInventoryComponent> Components)>> InventoryAsync(
        OciScanOwner? owner = null)
    {
        owner ??= OciScanOwner.Hosted(_version);
        var platforms = await _repo.GetInventoryPlatformsAsync(_org, owner);
        var components = new List<OciInventoryComponent>();
        await foreach (var c in _repo.StreamInventoryComponentsAsync(_org, owner, OciScanLimits.MaxComponents))
        {
            components.Add(c);
        }

        return platforms.Select(p => (p, components.Where(c => c.Platform == p.Platform).ToList())).ToList();
    }

    // Every stored component matches every named advisory.
    private static OciScanMatchRequest Matches(
        IReadOnlyList<(OciInventoryPlatform Platform, List<OciInventoryComponent> Components)> inventory,
        IReadOnlyList<string> vulns, IReadOnlyList<string>? matchGaps = null)
        => new(
            inventory.Select(i => new OciScanMatchPlatform(
                i.Platform.Platform, i.Platform.Id, "remote", "0.5.0", matchGaps ?? [],
                vulns.Count == 0 ? [] : i.Components.Select(c => new OciScanMatchFinding(c.Id, vulns)).ToList())).ToList(),
            vulns.Select(Record).ToList(),
            null);

    private static JsonElement Record(string id) => JsonDocument.Parse($$"""
        {
          "id": "{{id}}",
          "summary": "openssl issue {{id}}",
          "severity": [{ "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }],
          "affected": [{ "package": { "ecosystem": "Debian:12", "name": "openssl" }, "versions": ["3.0.11-1~deb12u1"] }]
        }
        """).RootElement.Clone();

    private async Task<List<string>> FindingsAsync() => (await QueryAsync<string>(
        """
        SELECT v.osv_id FROM oci_component_vulns cv JOIN vulnerabilities v ON v.id = cv.vuln_id
        ORDER BY v.osv_id
        """)).ToList();

    private async Task<List<string>> LinksAsync() => (await QueryAsync<string>(
        """
        SELECT v.osv_id FROM package_version_vulns pvv JOIN vulnerabilities v ON v.id = pvv.vuln_id
        WHERE pvv.package_version_id = @version ORDER BY v.osv_id
        """, new { version = _version })).ToList();

    private async Task<IReadOnlyList<T>> QueryAsync<T>(string sql, object? args = null)
    {
        await using var conn = await _db.OpenAsync();
        return (await conn.QueryAsync<T>(sql, args)).AsList();
    }

    private async Task<int> CountAsync(string sql)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.ExecuteScalarAsync<int>(sql);
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
            _events, new InProcessDistributedLock(TimeProvider.System),
            new Dependably.Infrastructure.Alerts.AlertService(
                new Dependably.Infrastructure.Alerts.AlertRepository(_db, _clock),
                new Dependably.Infrastructure.Alerts.NoOpAlertNotifier(),
                NullLogger<Dependably.Infrastructure.Alerts.AlertService>.Instance),
            new SbomComponentScanner(realOsv, vulns, new SbomComponentVulnRepository(_db, _clock), NullLogger<SbomComponentScanner>.Instance),
            TestSbomPolicy.Service(_db, _clock),
            TestEnrichment.Unused(),
            TestEnrichment.NoConnection()));
    }

    private sealed class EventCapture : IPackageEventSink
    {
        private readonly ConcurrentQueue<PackageEventEnvelope> _seen = new();

        public List<string> Vuln => _seen.Where(e => e.EventType == Dependably.Infrastructure.Audit.Events.PackageEvents.TypeVuln).Select(e => e.DataJson).ToList();

        public void Dispatch(PackageEventEnvelope envelope) => _seen.Enqueue(envelope);
    }
}
