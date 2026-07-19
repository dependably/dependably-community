using System.Formats.Tar;
using System.IO.Compression;
using System.Text;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit;

/// <summary>
/// Covers the license-backfill background service: the mixed same-tick batch (license found,
/// none present, blob missing — every case stamps license_checked_at), the air-gap / disabled-job
/// short-circuit, that a stamped artifact is never re-scanned, and that a full batch of failing
/// (unstampable) rows cannot starve newer rows within the same pass (keyset-pagination regression).
/// </summary>
[Trait("Category", "Unit")]
public sealed class LicenseBackfillServiceTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen();

    public async Task InitializeAsync() => await new SchemaInitializer(_db).InitializeAsync();

    public async Task DisposeAsync() => await _db.DisposeAsync();

    [Fact]
    public async Task BackfillPass_MixedBatch_WritesLicenseWhenPresent_AlwaysStamps()
    {
        var blobs = new InMemoryBlobStore();

        // 1. npm tarball whose package.json declares a license → row written + stamped.
        string withKey = "proxy/" + new string('a', 64);
        await blobs.PutAsync(withKey, NpmTarball("with-lic", "1.0.0", license: "MIT"));
        string idWith = await SeedCacheArtifactAsync("npm", "with-lic", "1.0.0", withKey, "with-lic-1.0.0.tgz");

        // 2. npm tarball with no license field → no row, still stamped.
        string noneKey = "proxy/" + new string('b', 64);
        await blobs.PutAsync(noneKey, NpmTarball("no-lic", "1.0.0", license: null));
        string idNone = await SeedCacheArtifactAsync("npm", "no-lic", "1.0.0", noneKey, "no-lic-1.0.0.tgz");

        // 3. cache_artifact row whose blob was evicted (crash window left the row) → no row,
        //    still stamped, no throw.
        string missingKey = "proxy/" + new string('c', 64);
        string idMissing = await SeedCacheArtifactAsync("npm", "gone", "1.0.0", missingKey, "gone-1.0.0.tgz");

        // 4. Go module zip whose root LICENSE classifies to a known SPDX id → row written +
        //    stamped, exercising the golang ecosystem alongside npm in the same pass.
        string goKey = "proxy/" + new string('h', 64);
        await blobs.PutAsync(goKey, GoModuleZip("example.com/with-lic", "v1.0.0", SpdxTextFixtures.Text("MIT")));
        string idGoWith = await SeedCacheArtifactAsync("golang", "example.com/with-lic", "v1.0.0", goKey, "v1.0.0.zip");

        // 5. Maven .pom row whose <licenses> block maps to a known SPDX id → row written +
        //    stamped, exercising maven alongside npm/golang in the same pass.
        string pomKey = "proxy/" + new string('i', 64);
        await blobs.PutAsync(pomKey, MavenPom("The Apache Software License, Version 2.0"));
        string idMavenWith = await SeedCacheArtifactAsync(
            "maven", "com.example:widget", "1.0.0", pomKey, "widget-1.0.0.pom");

        // 6. Maven .jar row (same ecosystem, no license signal in the bytes) → never a candidate,
        //    so it is left unstamped by this pass regardless of what the blob contains.
        string jarKey = "proxy/" + new string('j', 64);
        await blobs.PutAsync(jarKey, new MemoryStream(Encoding.UTF8.GetBytes("not-a-pom")));
        string idMavenJar = await SeedCacheArtifactAsync(
            "maven", "com.example:widget", "1.0.0", jarKey, "widget-1.0.0.jar");

        var service = BuildService(blobs);
        await service.RunBackfillPassAsync(CancellationToken.None);

        // 1: license extracted and attached to the global plane.
        Assert.Equal(new[] { "MIT" }, await LicensesForAsync(idWith));
        // 2 + 3: no license attached.
        Assert.Empty(await LicensesForAsync(idNone));
        Assert.Empty(await LicensesForAsync(idMissing));
        // 4: golang license extracted in the same pass as the npm rows above.
        Assert.Equal(new[] { "MIT" }, await LicensesForAsync(idGoWith));
        // 5: maven .pom license extracted in the same pass.
        Assert.Equal(new[] { "Apache-2.0" }, await LicensesForAsync(idMavenWith));
        // 6: maven .jar row never became a candidate — no license row.
        Assert.Empty(await LicensesForAsync(idMavenJar));

        // All five candidates stamped at the frozen instant, regardless of outcome.
        string expected = TestTime.KnownNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
        Assert.Equal(expected, await CheckedAtAsync(idWith));
        Assert.Equal(expected, await CheckedAtAsync(idNone));
        Assert.Equal(expected, await CheckedAtAsync(idMissing));
        Assert.Equal(expected, await CheckedAtAsync(idGoWith));
        Assert.Equal(expected, await CheckedAtAsync(idMavenWith));
        // The .jar row was never a backfill candidate, so it is not stamped by this pass.
        Assert.Null(await CheckedAtAsync(idMavenJar));
    }

    [Fact]
    public async Task BackfillPass_StampedArtifact_NotRescanned()
    {
        var blobs = new InMemoryBlobStore();
        string key = "proxy/" + new string('d', 64);
        await blobs.PutAsync(key, NpmTarball("pkg", "1.0.0", license: "MIT"));
        string id = await SeedCacheArtifactAsync("npm", "pkg", "1.0.0", key, "pkg-1.0.0.tgz");

        var service = BuildService(blobs);
        await service.RunBackfillPassAsync(CancellationToken.None);
        Assert.Equal(new[] { "MIT" }, await LicensesForAsync(id));

        // A second pass finds nothing to do — the row is already checked, so no duplicate rows.
        _clock.Advance(TimeSpan.FromDays(1));
        await service.RunBackfillPassAsync(CancellationToken.None);
        Assert.Equal(new[] { "MIT" }, await LicensesForAsync(id));
        // Original stamp instant preserved (not re-stamped).
        Assert.Equal(TestTime.KnownNow.ToString("yyyy-MM-ddTHH:mm:ssZ"), await CheckedAtAsync(id));
    }

    [Fact]
    public async Task BackfillPass_GolangCandidate_WithLicense_WritesRow_Stamped()
    {
        var blobs = new InMemoryBlobStore();
        string key = "proxy/" + new string('f', 64);
        await blobs.PutAsync(key, GoModuleZip("example.com/gomod", "v1.0.0", SpdxTextFixtures.Text("MIT")));
        string id = await SeedCacheArtifactAsync("golang", "example.com/gomod", "v1.0.0", key, "v1.0.0.zip");

        var service = BuildService(blobs);
        await service.RunBackfillPassAsync(CancellationToken.None);

        Assert.Equal(new[] { "MIT" }, await LicensesForAsync(id));
        Assert.Equal(TestTime.KnownNow.ToString("yyyy-MM-ddTHH:mm:ssZ"), await CheckedAtAsync(id));
    }

    [Fact]
    public async Task BackfillPass_GolangCandidate_MissingBlob_StampedNoRow()
    {
        var blobs = new InMemoryBlobStore();
        string key = "proxy/" + new string('g', 64);
        string id = await SeedCacheArtifactAsync("golang", "example.com/gone", "v1.0.0", key, "v1.0.0.zip");

        var service = BuildService(blobs);
        await service.RunBackfillPassAsync(CancellationToken.None);

        Assert.Empty(await LicensesForAsync(id));
        Assert.Equal(TestTime.KnownNow.ToString("yyyy-MM-ddTHH:mm:ssZ"), await CheckedAtAsync(id));
    }

    [Fact]
    public async Task BackfillPass_MavenPomCandidate_WithLicense_WritesRow_Stamped()
    {
        var blobs = new InMemoryBlobStore();
        string key = "proxy/" + new string('k', 64);
        await blobs.PutAsync(key, MavenPom("The Apache Software License, Version 2.0"));
        string id = await SeedCacheArtifactAsync(
            "maven", "com.example:widget", "1.0.0", key, "widget-1.0.0.pom");

        var service = BuildService(blobs);
        await service.RunBackfillPassAsync(CancellationToken.None);

        Assert.Equal(new[] { "Apache-2.0" }, await LicensesForAsync(id));
        Assert.Equal(TestTime.KnownNow.ToString("yyyy-MM-ddTHH:mm:ssZ"), await CheckedAtAsync(id));
    }

    [Fact]
    public async Task BackfillPass_MavenPomCandidate_MissingBlob_StampedNoRow()
    {
        var blobs = new InMemoryBlobStore();
        string key = "proxy/" + new string('l', 64);
        string id = await SeedCacheArtifactAsync(
            "maven", "com.example:gone", "1.0.0", key, "gone-1.0.0.pom");

        var service = BuildService(blobs);
        await service.RunBackfillPassAsync(CancellationToken.None);

        Assert.Empty(await LicensesForAsync(id));
        Assert.Equal(TestTime.KnownNow.ToString("yyyy-MM-ddTHH:mm:ssZ"), await CheckedAtAsync(id));
    }

    [Fact]
    public async Task ListNeedingLicenseBackfillAsync_MavenJarRow_ExcludedFromCandidates()
    {
        // Seed a maven .pom row and a maven .jar row, both license_checked_at NULL — only the
        // .pom row is a backfill candidate; the .jar row is filename-excluded entirely (Maven
        // cache rows mix jars, poms, and sidecars under one ecosystem, and the license signal
        // lives only in the .pom).
        string pomId = await SeedCacheArtifactAsync(
            "maven", "com.example:widget", "1.0.0", "proxy/" + new string('m', 64), "widget-1.0.0.pom");
        await SeedCacheArtifactAsync(
            "maven", "com.example:widget", "1.0.0", "proxy/" + new string('n', 64), "widget-1.0.0.jar");

        var repo = new CacheArtifactRepository(_db);
        var candidates = await repo.ListNeedingLicenseBackfillAsync(limit: 200);

        Assert.Single(candidates);
        Assert.Equal(pomId, candidates[0].Id);
        Assert.Equal("widget-1.0.0.pom", candidates[0].Filename);
    }

    [Fact]
    public async Task BackfillPass_JobDisabled_ShortCircuits_NothingStamped()
    {
        var blobs = new InMemoryBlobStore();
        string key = "proxy/" + new string('e', 64);
        await blobs.PutAsync(key, NpmTarball("pkg", "1.0.0", license: "MIT"));
        string id = await SeedCacheArtifactAsync("npm", "pkg", "1.0.0", key, "pkg-1.0.0.tgz");

        var service = BuildService(blobs, airGapped: true);
        await service.RunBackfillPassAsync(CancellationToken.None);

        Assert.Empty(await LicensesForAsync(id));
        Assert.Null(await CheckedAtAsync(id));
    }

    [Fact]
    public async Task BackfillPass_EntireBatchFails_CursorAdvancesPastIt_NewerRowStillScannedSameTick()
    {
        // Regression for progress starvation: seed exactly BatchSize (100) oldest rows whose blob
        // reads always throw (never stamped, since ProcessArtifactAsync catches and skips the
        // stamp on unexpected failure) plus one newer, healthy row. Without a keyset cursor, the
        // plain "WHERE license_checked_at IS NULL ... LIMIT 100" would re-return the identical 100
        // failing rows on every batch read forever, and the newer row would never be reached —
        // not within this tick, and not on any future tick either. With the cursor advancing from
        // the last row of the failing batch (by (first_cached_at, id), regardless of outcome), the
        // second batch read reaches the healthy row within the SAME tick.
        var failingKeys = new HashSet<string>();
        var inner = new InMemoryBlobStore();
        var t = TestTime.KnownNow;

        for (int i = 0; i < 100; i++)
        {
            string key = "proxy/" + i.ToString("x").PadLeft(64, '0');
            failingKeys.Add(key);
            await inner.PutAsync(key, NpmTarball($"failing-{i}", "1.0.0", license: "MIT"));
            await SeedCacheArtifactAsync(
                "npm", $"failing-{i}", "1.0.0", key, $"failing-{i}-1.0.0.tgz",
                firstCachedAt: t.AddDays(-2).AddSeconds(-i));
        }

        string healthyKey = "proxy/" + new string('9', 64);
        await inner.PutAsync(healthyKey, NpmTarball("healthy", "1.0.0", license: "Apache-2.0"));
        string healthyId = await SeedCacheArtifactAsync(
            "npm", "healthy", "1.0.0", healthyKey, "healthy-1.0.0.tgz",
            firstCachedAt: t);

        var blobs = new FailingBlobStore(inner, failingKeys);
        var service = BuildService(blobs);
        await service.RunBackfillPassAsync(CancellationToken.None);

        // The healthy, newer row was reached and processed within this same tick.
        Assert.Equal(new[] { "Apache-2.0" }, await LicensesForAsync(healthyId));
        Assert.Equal(TestTime.KnownNow.ToString("yyyy-MM-ddTHH:mm:ssZ"), await CheckedAtAsync(healthyId));

        // None of the 100 failing rows were stamped — they remain in the queue for a later pass.
        var remaining = await new CacheArtifactRepository(_db).ListNeedingLicenseBackfillAsync(limit: 200);
        Assert.Equal(100, remaining.Count);
        Assert.All(remaining, r => Assert.StartsWith("failing-", r.Name));
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private LicenseBackfillService BuildService(IBlobStore blobs, bool airGapped = false)
    {
        var tiered = new TieredBlobStorage(blobs, blobs);
        var config = new ConfigurationBuilder().AddInMemoryCollection().Build();
        return new LicenseBackfillService(
            new CacheArtifactRepository(_db),
            new LicenseRepository(_db, _clock, TestNormalizers.License(_db)),
            tiered,
            new StubAirGap(airGapped),
            config,
            NullLogger<LicenseBackfillService>.Instance,
            _clock,
            new Dependably.Infrastructure.Redis.InProcessDistributedLock(_clock));
    }

    private async Task<string> SeedCacheArtifactAsync(
        string ecosystem, string name, string version, string blobKey, string filename,
        DateTimeOffset? firstCachedAt = null)
    {
        await using var conn = await _db.OpenAsync();
        string id = Guid.NewGuid().ToString("N");
        if (firstCachedAt is { } fca)
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO cache_artifact
                    (id, ecosystem, name, version, filename, blob_key, content_hash, first_cached_at)
                VALUES (@id, @ecosystem, @name, @version, @filename, @blobKey, 'h', @firstCachedAt)
                """,
                new { id, ecosystem, name, version, filename, blobKey, firstCachedAt = fca });
        }
        else
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash)
                VALUES (@id, @ecosystem, @name, @version, @filename, @blobKey, 'h')
                """,
                new { id, ecosystem, name, version, filename, blobKey });
        }
        return id;
    }

    private async Task<string[]> LicensesForAsync(string cacheArtifactId)
    {
        await using var conn = await _db.OpenAsync();
        var rows = await conn.QueryAsync<string>(
            """
            SELECT license_spdx FROM package_version_licenses
            WHERE cache_artifact_id = @id AND owner_kind = 'cache_artifact'
            ORDER BY license_spdx
            """,
            new { id = cacheArtifactId });
        return rows.ToArray();
    }

    private async Task<string?> CheckedAtAsync(string cacheArtifactId)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.QuerySingleAsync<string?>(
            "SELECT license_checked_at FROM cache_artifact WHERE id = @id", new { id = cacheArtifactId });
    }

    // Builds a minimal npm tarball with package/package.json carrying the given license (or none).
    private static MemoryStream NpmTarball(string name, string version, string? license)
    {
        string pkgJson = license is null
            ? $$"""{"name":"{{name}}","version":"{{version}}"}"""
            : $$"""{"name":"{{name}}","version":"{{version}}","license":"{{license}}"}""";

        byte[] contentBytes = Encoding.UTF8.GetBytes(pkgJson);
        using var ms = new MemoryStream();
        using (var gz = new GZipStream(ms, CompressionMode.Compress, leaveOpen: true))
        using (var tw = new TarWriter(gz, leaveOpen: true))
        {
            tw.WriteEntry(new PaxTarEntry(TarEntryType.RegularFile, "package/package.json")
            {
                DataStream = new MemoryStream(contentBytes),
            });
        }
        return new MemoryStream(ms.ToArray());
    }

    // Builds a minimal Go module zip whose root LICENSE entry carries the given text, using the
    // GOPROXY zip-entry naming convention ({module}@{version}/…).
    private static MemoryStream GoModuleZip(string module, string version, string licenseText)
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            var entry = zip.CreateEntry($"{module}@{version}/LICENSE");
            using var s = entry.Open();
            using var w = new StreamWriter(s, new UTF8Encoding(false));
            w.Write(licenseText);
        }
        return new MemoryStream(ms.ToArray());
    }

    // Builds a minimal Maven POM whose single <licenses><license><name> declares the given text.
    private static MemoryStream MavenPom(string licenseName)
    {
        string xml = $"""
            <?xml version="1.0" encoding="UTF-8"?>
            <project xmlns="http://maven.apache.org/POM/4.0.0">
              <modelVersion>4.0.0</modelVersion>
              <groupId>com.example</groupId>
              <artifactId>widget</artifactId>
              <version>1.0.0</version>
              <licenses>
                <license>
                  <name>{licenseName}</name>
                </license>
              </licenses>
            </project>
            """;
        return new MemoryStream(Encoding.UTF8.GetBytes(xml));
    }

    private sealed class StubAirGap : IAirGapMode
    {
        public StubAirGap(bool enabled) => IsEnabled = enabled;
        public bool IsEnabled { get; }
        public IReadOnlySet<string> DisabledJobs => new HashSet<string>();
        public bool IsJobDisabled(string jobName) => IsEnabled;
    }

    /// <summary>
    /// Wraps an <see cref="IBlobStore"/> and throws from <see cref="GetAsync"/> for a configured
    /// set of keys, simulating a blob-backend fault (as opposed to a clean cache miss, which
    /// returns null). Used to prove the backfill service's failure handling never re-stamps a row
    /// it couldn't process, and that the keyset cursor still advances past it.
    /// </summary>
    private sealed class FailingBlobStore : IBlobStore
    {
        private readonly IBlobStore _inner;
        private readonly IReadOnlySet<string> _throwOnKeys;

        public FailingBlobStore(IBlobStore inner, IReadOnlySet<string> throwOnKeys)
        {
            _inner = inner;
            _throwOnKeys = throwOnKeys;
        }

        public Task<Stream?> GetAsync(string key, CancellationToken ct = default) =>
            _throwOnKeys.Contains(key)
                ? throw new IOException($"simulated blob backend fault for {key}")
                : _inner.GetAsync(key, ct);

        public Task PutAsync(string key, Stream data, CancellationToken ct = default) =>
            _inner.PutAsync(key, data, ct);

        public Task<bool> ExistsAsync(string key, CancellationToken ct = default) =>
            _inner.ExistsAsync(key, ct);

        public Task DeleteAsync(string key, CancellationToken ct = default) =>
            _inner.DeleteAsync(key, ct);

        public Task<long> GetTotalSizeAsync(CancellationToken ct = default) =>
            _inner.GetTotalSizeAsync(ct);

        public Task<RangedStream?> GetRangeAsync(string key, long from, long to, CancellationToken ct = default) =>
            _inner.GetRangeAsync(key, from, to, ct);

        public IAsyncEnumerable<BlobInfo> ListAsync(string prefix, CancellationToken ct = default) =>
            _inner.ListAsync(prefix, ct);
    }
}
