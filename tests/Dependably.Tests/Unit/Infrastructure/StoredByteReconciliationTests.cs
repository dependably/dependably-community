using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Redis;
using Dependably.Infrastructure.Usage;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// The stored-byte phase of <see cref="UsageReconciliationService"/>: per plane, the bytes the
/// blob store holds against the sizes the metadata records over distinct store keys.
/// </summary>
[Trait("Category", "Unit")]
public sealed class StoredByteReconciliationTests : IAsyncLifetime
{
    private static readonly DateTimeOffset Now = new(2026, 9, 29, 2, 0, 0, TimeSpan.Zero);

    private readonly TestMetadataStore _db = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen(Now);
    private readonly InMemoryBlobStore _registry;
    private readonly InMemoryBlobStore _cache;

    public StoredByteReconciliationTests()
    {
        _registry = new InMemoryBlobStore(_clock);
        _cache = new InMemoryBlobStore(_clock);
    }

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme'), ('o2', 'globex')");
        await conn.ExecuteAsync(
            "INSERT INTO packages (id, org_id, ecosystem, name, purl_name) VALUES ('p1', 'o1', 'pypi', 'lib', 'lib')");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private TieredBlobStorage Unsplit() => new(_registry, _registry);

    private TieredBlobStorage Split() => new(_cache, _registry);

    private StoredByteReconciler Reconciler(TieredBlobStorage tiers)
        => new(tiers, new StoredBytesRepository(_db));

    private UsageReconciliationService Service(TieredBlobStorage tiers)
    {
        var cfg = new ConfigurationBuilder().AddInMemoryCollection([]).Build();
        return new UsageReconciliationService(
            new UsageRollupRepository(_db), Reconciler(tiers), cfg, new AirGapMode(cfg),
            NullLogger<UsageReconciliationService>.Instance, _clock,
            new InProcessDistributedLock(_clock));
    }

    private static async Task PutAsync(IBlobStore store, string key, int size)
        => await store.PutAsync(key, new MemoryStream(new byte[size]));

    private static string Sha(char c) => new(c, 64);

    private static string HostedKey(string filename, char sha = 'a')
        => BlobKeys.HostedArtifact("o1", "pypi", "lib", "1.0.0", Sha(sha), filename);

    private async Task ExecAsync(string sql, object? args = null)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(sql, args);
    }

    private Task SeedVersionAsync(string id, string blobKey, long size)
        => ExecAsync(
            """
            INSERT INTO package_versions (id, package_id, version, purl, blob_key, size_bytes)
            VALUES (@id, 'p1', @id, 'pkg:pypi/lib@' || @id, @blobKey, @size)
            """,
            new { id, blobKey, size });

    private Task SeedCacheArtifactAsync(string id, string name, string blobKey, long size)
        => ExecAsync(
            """
            INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash, size_bytes)
            VALUES (@id, 'npm', @name, '1.0.0', @name || '.tgz', @blobKey, 'h', @size)
            """,
            new { id, name, blobKey, size });

    private static PlaneByteTally PlaneOf(StoredByteReport report, string plane)
        => report.Planes.Single(p => p.Plane == plane);

    [Fact]
    public async Task An_empty_deployment_passes_with_every_plane_zero_against_zero()
    {
        var report = await Reconciler(Unsplit()).MeasureAsync(CancellationToken.None);

        Assert.Equal(BlobKeys.PlanePrefixes, report.Planes.Select(p => p.Plane));
        Assert.All(report.Planes, p =>
        {
            Assert.Equal(0, p.StoreBytes);
            Assert.Equal(0, p.MetadataBytes);
        });
        await Service(Unsplit()).RunReconciliationPassAsync(CancellationToken.None);
    }

    [Fact]
    public async Task Drift_within_two_percent_passes()
    {
        string key = HostedKey("lib-1.0.0.tar.gz");
        await PutAsync(_registry, key, 1000);
        await SeedVersionAsync("v1", key, 1015);

        var hosted = PlaneOf(await Reconciler(Unsplit()).MeasureAsync(CancellationToken.None), "hosted/");
        Assert.Equal(1000, hosted.StoreBytes);
        Assert.Equal(1015, hosted.MetadataBytes);

        await Service(Unsplit()).RunReconciliationPassAsync(CancellationToken.None);
    }

    [Fact]
    public async Task Drift_beyond_two_percent_fails_and_names_only_the_drifted_plane()
    {
        string hostedKey = HostedKey("lib-1.0.0.tar.gz");
        await PutAsync(_registry, hostedKey, 1100);
        await SeedVersionAsync("v1", hostedKey, 1000);

        // A second plane in agreement, so the failure has to single out hosted/.
        string proxyDbKey = BlobKeys.Proxy(Sha('b')) + "/left-pad-1.0.0.tgz";
        await PutAsync(_registry, BlobKeys.StoreKey(proxyDbKey), 500);
        await SeedCacheArtifactAsync("ca1", "left-pad", proxyDbKey, 500);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => Service(Unsplit()).RunReconciliationPassAsync(CancellationToken.None));

        Assert.Contains("hosted/: store=1100 bytes, metadata=1000 bytes", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("proxy/:", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_rollup_mismatch_and_a_byte_drift_fail_the_run_together()
    {
        var at = UsageRollupRepository.UtcMidnight(new DateOnly(2026, 9, 24));
        await new UsageEventRepository(_db).InsertBatchAsync(
        [
            UsageEvent.Create(Guid.NewGuid(), "o1", UsageMeters.EgressBytes, UsageDelivery.Streamed, 1000, "npm", null, at),
        ]);
        var rollups = new UsageRollupRepository(_db);
        await rollups.RecomputeHourlyAsync(at, at.AddHours(1), Now);
        await rollups.RecomputeDailyEgressAsync(new DateOnly(2026, 9, 24), new DateOnly(2026, 9, 25), Now);
        await ExecAsync("UPDATE usage_daily SET quantity = 500 WHERE org_id = 'o1'");

        await PutAsync(_registry, HostedKey("lib-1.0.0.tar.gz"), 2000);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => Service(Unsplit()).RunReconciliationPassAsync(CancellationToken.None));

        Assert.Contains("quantity mismatch", ex.Message, StringComparison.Ordinal);
        Assert.Contains("hosted/: store=2000 bytes, metadata=0 bytes", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Rows_sharing_bytes_count_once_on_the_metadata_side()
    {
        // Two proxy coordinates whose upstream bytes are identical: one object, two rows, and a
        // tenant binding naming the same bytes again.
        string sha = Sha('c');
        await PutAsync(_registry, BlobKeys.Proxy(sha), 700);
        await SeedCacheArtifactAsync("ca1", "a", BlobKeys.Proxy(sha) + "/a-1.0.0.tgz", 700);
        await SeedCacheArtifactAsync("ca2", "b", BlobKeys.Proxy(sha) + "/b-1.0.0.tgz", 700);
        await ExecAsync(
            "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id, blob_key, size_bytes) VALUES ('o2', 'ca1', @key, 700)",
            new { key = BlobKeys.Proxy(sha) + "/a-1.0.0.tgz" });

        // One OCI digest held by two orgs: rows are per (digest, org), the object is one.
        string ociKey = BlobKeys.OciBlob("sha256", Sha('d'));
        await PutAsync(_registry, ociKey, 900);
        await ExecAsync(
            """
            INSERT INTO oci_blobs (digest, org_id, media_type, size_bytes, blob_key)
            VALUES (@digest, 'o1', 'application/vnd.oci.image.layer.v1.tar+gzip', 900, @key),
                   (@digest, 'o2', 'application/vnd.oci.image.layer.v1.tar+gzip', 900, @key)
            """,
            new { digest = "sha256:" + Sha('d'), key = ociKey });

        // A multi-file version: the parent row names its first file with the sum of both files.
        string wheel = HostedKey("lib-1.0.0-py3-none-any.whl", 'e');
        string sdist = HostedKey("lib-1.0.0.tar.gz", 'f');
        await PutAsync(_registry, wheel, 100);
        await PutAsync(_registry, sdist, 200);
        await SeedVersionAsync("v1", wheel, 300);
        await ExecAsync(
            """
            INSERT INTO package_version_files (id, package_version_id, org_id, filename, blob_key, size_bytes)
            VALUES ('f1', 'v1', 'o1', 'lib-1.0.0-py3-none-any.whl', @wheel, 100),
                   ('f2', 'v1', 'o1', 'lib-1.0.0.tar.gz', @sdist, 200)
            """,
            new { wheel, sdist });

        var report = await Reconciler(Unsplit()).MeasureAsync(CancellationToken.None);

        var proxy = PlaneOf(report, "proxy/");
        Assert.Equal((700, 700, 1), (proxy.StoreBytes, proxy.MetadataBytes, proxy.MetadataKeys));
        var oci = PlaneOf(report, "oci/");
        Assert.Equal((900, 900, 1), (oci.StoreBytes, oci.MetadataBytes, oci.MetadataKeys));
        var hosted = PlaneOf(report, "hosted/");
        Assert.Equal((300, 300, 2), (hosted.StoreBytes, hosted.MetadataBytes, hosted.MetadataKeys));

        await Service(Unsplit()).RunReconciliationPassAsync(CancellationToken.None);
    }

    [Fact]
    public async Task Snupkg_objects_are_left_out_of_both_sides_and_reported()
    {
        string nupkg = HostedKey("lib.1.0.0.nupkg");
        string snupkg = HostedKey("lib.1.0.0.snupkg", 'b');
        await PutAsync(_registry, nupkg, 400);
        await PutAsync(_registry, snupkg, 10_000);
        await SeedVersionAsync("v1", nupkg, 400);
        await ExecAsync(
            """
            INSERT INTO nuget_symbol_index (id, org_id, package_version_id, pdb_filename, ssqp_key, snupkg_blob_key, entry_path)
            VALUES ('s1', 'o1', 'v1', 'lib.pdb', @ssqp, @snupkg, 'lib.pdb')
            """,
            new { ssqp = new string('0', 32) + "ffffffff", snupkg });

        var report = await Reconciler(Unsplit()).MeasureAsync(CancellationToken.None);

        var hosted = PlaneOf(report, "hosted/");
        Assert.Equal((400, 400, 0), (hosted.StoreBytes, hosted.MetadataBytes, hosted.NullSizeKeys));
        Assert.Equal(10_000, report.ExcludedSymbolBytes);
        await Service(Unsplit()).RunReconciliationPassAsync(CancellationToken.None);
    }

    [Fact]
    public async Task Staging_and_recordless_objects_are_left_out_and_reported()
    {
        await PutAsync(_registry, BlobKeys.OciStaging("tok"), 5000);
        await PutAsync(_registry, BlobKeys.RpmRepodataProxy(Sha('a')), 3000);
        await PutAsync(_registry, BlobKeys.HexDocs("o1", "plug", "1.0.0"), 2000);
        await PutAsync(_registry, BlobKeys.Go("o1", "example.com/m", "v1.0.0", "mod"), 10);
        await PutAsync(_registry, BlobKeys.Go("o1", "example.com/m", "v1.0.0", "info"), 20);

        var report = await Reconciler(Unsplit()).MeasureAsync(CancellationToken.None);

        Assert.All(report.Planes, p => Assert.Equal(0, p.StoreBytes));
        Assert.Equal(5000, report.ExcludedStagingBytes);
        Assert.Equal(3000 + 2000 + 10 + 20, report.RecordlessBytes);
        await Service(Unsplit()).RunReconciliationPassAsync(CancellationToken.None);
    }

    [Fact]
    public async Task A_row_with_no_recorded_size_is_counted_and_named_in_the_failure()
    {
        string sha = Sha('9');
        string goKey = BlobKeys.Go("o2", "example.com/m", "v1.0.0", "zip");
        await PutAsync(_registry, goKey, 800);
        await SeedCacheArtifactAsync("ca1", "m", BlobKeys.Proxy(sha) + "/m.tgz", 0);
        await ExecAsync(
            "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id, blob_key, size_bytes) VALUES ('o2', 'ca1', @goKey, NULL)",
            new { goKey });

        var go = PlaneOf(await Reconciler(Unsplit()).MeasureAsync(CancellationToken.None), "go/");
        Assert.Equal((800, 0, 1, 1), (go.StoreBytes, go.MetadataBytes, go.MetadataKeys, go.NullSizeKeys));

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => Service(Unsplit()).RunReconciliationPassAsync(CancellationToken.None));
        Assert.Contains("go/: store=800 bytes, metadata=0 bytes (1 key(s) with a NULL size)", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Split_tiers_are_both_walked()
    {
        // Proxied bytes some ecosystems keep on the registry tier, and a hosted artefact.
        string sha = Sha('7');
        await PutAsync(_cache, BlobKeys.Proxy(sha), 600);
        await PutAsync(_registry, BlobKeys.Cargo("o1", "serde", "1.0.0"), 250);
        await SeedCacheArtifactAsync("ca1", "a", BlobKeys.Proxy(sha) + "/a.tgz", 600);
        await ExecAsync(
            """
            INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash, size_bytes)
            VALUES ('ca2', 'cargo', 'serde', '1.0.0', 'serde-1.0.0.crate', @key, 'h', 250)
            """,
            new { key = BlobKeys.Cargo("o1", "serde", "1.0.0") });

        var report = await Reconciler(Split()).MeasureAsync(CancellationToken.None);

        Assert.True(report.TiersSplit);
        Assert.Equal(600, PlaneOf(report, "proxy/").StoreBytes);
        Assert.Equal(250, PlaneOf(report, "cargo/").StoreBytes);
        await Service(Split()).RunReconciliationPassAsync(CancellationToken.None);
    }

    [Fact]
    public async Task One_store_behind_both_tiers_is_walked_once()
    {
        string key = HostedKey("lib-1.0.0.tar.gz");
        await PutAsync(_registry, key, 1000);
        await SeedVersionAsync("v1", key, 1000);

        var report = await Reconciler(Unsplit()).MeasureAsync(CancellationToken.None);

        Assert.False(report.TiersSplit);
        var hosted = PlaneOf(report, "hosted/");
        Assert.Equal((1000, 1), (hosted.StoreBytes, hosted.StoreObjects));
    }
}
