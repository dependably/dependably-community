using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.OciScan;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit.OciScan;

/// <summary>
/// The sweep queues what push and pull could not, only for orgs that run a scanner, and stands
/// down when scanning is off, the job is disabled, or the node is air-gapped.
/// </summary>
[Trait("Category", "Unit")]
public sealed class OciScanSweepServiceTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private string _scanning = null!;
    private string _idle = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        _scanning = await OrgSeeder.InsertAsync(_db, "sweep-scanning");
        _idle = await OrgSeeder.InsertAsync(_db, "sweep-idle");
        foreach (string org in new[] { _scanning, _idle })
        {
            string pkg = await PackageSeeder.InsertAsync(_db, org, "oci", "team/app");
            await PackageSeeder.InsertVersionAsync(_db, pkg, "sha256:" + new string('2', 64), "pkg:oci/app");
        }

        await new OciScanRepository(_db).TouchScannerAsync(_scanning, "2026-06-15T12:00:00.000Z", "0.3.0", "remote", null);
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    [Fact]
    public async Task QueuesMissingImages_OnlyForOrgsThatRunAScanner()
    {
        Assert.Equal(1, await Build(enabled: true).RunPassAsync(default));

        await using var conn = await _db.OpenAsync();
        Assert.Equal(1, await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM oci_scan_jobs WHERE org_id = @org", new { org = _scanning }));
        Assert.Equal(0, await conn.ExecuteScalarAsync<int>(
            "SELECT COUNT(*) FROM oci_scan_jobs WHERE org_id = @org", new { org = _idle }));
    }

    [Theory]
    [InlineData(false, null, null)]
    [InlineData(true, "DISABLE_BACKGROUND_JOBS", OciScanSweepService.JobName)]
    [InlineData(true, "DISABLE_BACKGROUND_JOBS", "true")]
    [InlineData(true, "DEPLOYMENT_MODE", "edge")]
    public async Task StandsDown_WhenOffNamedWholeSetOrEdge(bool enabled, string? switchKey, string? value)
    {
        var settings = new Dictionary<string, string?>();
        if (switchKey is not null)
        {
            settings[switchKey] = value;
        }

        Assert.Equal(0, await Build(enabled, settings).RunPassAsync(default));
    }

    [Fact]
    public async Task RunsUnderAirGap_BecauseItMakesNoOutboundCall()
    {
        var settings = new Dictionary<string, string?> { ["AIR_GAPPED"] = "true" };
        Assert.Equal(1, await Build(enabled: true, settings).RunPassAsync(default));
    }

    [Fact]
    public async Task AirGapPlusANamedEntry_StillStopsIt()
    {
        var settings = new Dictionary<string, string?>
        {
            ["AIR_GAPPED"] = "true",
            ["DISABLE_BACKGROUND_JOBS"] = OciScanSweepService.JobName,
        };
        Assert.Equal(0, await Build(enabled: true, settings).RunPassAsync(default));
    }

    // ── Coverage backfill ───────────────────────────────────────────────────────

    private static readonly string ListedChild = "sha256:" + new string('a', 64);

    [Fact]
    public async Task Backfill_MarksALegacyRowWhoseManifestIsUnreadable_AsNonCovering()
    {
        var store = new InMemoryBlobStore();
        string version = await SeedCoveredImageAsync("team/legacy", 'b', manifestDigest: null);

        await BuildWithReader(store).RunPassAsync(default);

        Assert.Equal(OciScanRepository.UnreadableMapDigest, await CoverageDigestAsync(version));
        Assert.Contains(version, await new OciScanRepository(_db).GetOwnersNotCoveringAsync(
            _scanning, [version], ListedChild));
    }

    [Fact]
    public async Task Backfill_RetriesAnUnknownRow_AndFillsItOnceTheManifestIsReadable()
    {
        var store = new InMemoryBlobStore();
        string digest = "sha256:" + new string('c', 64);
        string version = await SeedCoveredImageAsync(
            "team/retry", 'c', manifestDigest: OciScanRepository.UnreadableMapDigest);
        var sweep = BuildWithReader(store);

        await sweep.RunPassAsync(default);
        Assert.Equal(OciScanRepository.UnreadableMapDigest, await CoverageDigestAsync(version));

        await StoreManifestAsync(store, digest, "{\"schemaVersion\":2}");
        // The cursor wraps to the start on the pass after the last page.
        await sweep.RunPassAsync(default);
        await sweep.RunPassAsync(default);

        Assert.Equal(digest, await CoverageDigestAsync(version));
    }

    // A page of images the backfill cannot read must not starve an image behind it: the cursor
    // advances past every page, readable or not.
    [Fact]
    public async Task Backfill_AdvancesItsCursorPastPagesItCannotFill()
    {
        var store = new InMemoryBlobStore();
        var versions = new List<(string Version, string Digest)>();
        for (int i = 0; i < 51; i++)
        {
            string digest = "sha256:" + i.ToString("x").PadLeft(64, 'd');
            versions.Add((await SeedCoveredImageAsync("team/page" + i, 'd', manifestDigest: null, digest), digest));
        }

        // Only the owner that sorts last (past the first page of 50) has a readable manifest.
        var last = versions.OrderBy(v => v.Version, StringComparer.Ordinal).Last();
        await StoreManifestAsync(store, last.Digest, "{\"schemaVersion\":2}");
        var sweep = BuildWithReader(store);

        for (int pass = 0; pass < 3; pass++)
        {
            await sweep.RunPassAsync(default);
        }

        Assert.Equal(last.Digest, await CoverageDigestAsync(last.Version));
    }

    private async Task<string> SeedCoveredImageAsync(string repository, char fill, string? manifestDigest, string? digest = null)
    {
        digest ??= "sha256:" + new string(fill, 64);
        string version = await OciScanSeeder.HostedImageAsync(_db, _scanning, repository, digest);
        await OciScanSeeder.ResultAsync(_db, _scanning, OciScanOwner.Hosted(version), "linux/amd64", [],
            [new SeedComponent("zlib", 0, [])]);
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "UPDATE oci_scan_coverage SET manifest_digest = @manifestDigest WHERE package_version_id = @version",
            new { manifestDigest, version });
        return version;
    }

    private async Task StoreManifestAsync(InMemoryBlobStore store, string digest, string json)
    {
        string key = BlobKeys.OciBlob("sha256", digest[7..]);
        await store.PutAsync(key, new MemoryStream(System.Text.Encoding.UTF8.GetBytes(json)));
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO oci_blobs (digest, org_id, media_type, size_bytes, blob_key, origin)
            VALUES (@digest, @org, 'application/vnd.oci.image.manifest.v1+json', @size, @key, 'uploaded')
            """,
            new { digest, org = _scanning, size = json.Length, key });
    }

    private async Task<string?> CoverageDigestAsync(string version)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.ExecuteScalarAsync<string?>(
            "SELECT manifest_digest FROM oci_scan_coverage WHERE package_version_id = @version", new { version });
    }

    private OciScanSweepService BuildWithReader(IBlobStore store)
    {
        var config = new ConfigurationBuilder().Build();
        return new OciScanSweepService(
            new OciScanOptions { Enabled = true },
            new OciScanRepository(_db),
            config,
            new AirGapMode(config),
            NullLogger<OciScanSweepService>.Instance,
            TestTime.Frozen(),
            new Dependably.Infrastructure.Redis.InProcessDistributedLock(TimeProvider.System),
            new OciPlatformManifestReader(_db, new TieredBlobStorage(store, store), NullLogger<OciPlatformManifestReader>.Instance));
    }

    private OciScanSweepService Build(bool enabled, Dictionary<string, string?>? settings = null)
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(settings ?? []).Build();
        return new OciScanSweepService(
            new OciScanOptions { Enabled = enabled },
            new OciScanRepository(_db),
            config,
            new AirGapMode(config),
            NullLogger<OciScanSweepService>.Instance,
            TestTime.Frozen(),
            new Dependably.Infrastructure.Redis.InProcessDistributedLock(TimeProvider.System));
    }
}
