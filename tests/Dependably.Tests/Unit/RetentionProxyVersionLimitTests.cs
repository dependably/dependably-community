using Dapper;
using Dependably.Infrastructure;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit;

/// <summary>
/// Both proxy-plane retention passes — <see cref="RetentionService.EnforceVersionLimitAsync"/>'s
/// keep_versions cap and <see cref="RetentionService.EvictStaleBlobsAsync"/>'s keep_days age
/// filter — decide per VERSION, and evict a version whole or not at all.
///
/// cache_artifact is keyed UNIQUE (ecosystem, name, version, filename): one version owns one row
/// per file, and those rows carry independent timestamps. Judging rows would make keep_versions=5
/// retain about one real Maven version, and — on either pass — could drop a version's .pom while
/// keeping its .jar. That partial version still lists and still resolves, right up until the
/// missing file 404s, which is worse than either keeping or dropping the version whole.
/// </summary>
[Trait("Category", "Unit")]
public sealed class RetentionProxyVersionLimitTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly InMemoryBlobStore _blobs = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme')");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private RetentionService Build()
    {
        var cfg = new ConfigurationBuilder().Build();
        return new RetentionService(new RetentionService.Dependencies(
            _db, _blobs, new JwtRevocationRepository(_db, time: _clock),
            new InviteRepository(_db, _clock), new SamlConfigRepository(_db, _clock), new TrustedDeviceService(_db, _clock, cfg),
            cfg, new AirGapMode(cfg), NullLogger<RetentionService>.Instance, _clock,
            new Dependably.Infrastructure.Redis.InProcessDistributedLock(_clock),
            new Dependably.Protocol.OciOrphanBlobDeleter(
                _db, new Dependably.Storage.TieredBlobStorage(_blobs, _blobs),
                new Dependably.Protocol.OciBlobKeyLock()),
            new Dependably.Infrastructure.Mail.EmailOutboxRepository(_db, _clock),
            new Dependably.Infrastructure.Mail.EmailOutboxPolicy(cfg)));
    }

    // Seeds one proxied FILE of a version, with its blob, for org 'o1'.
    //
    // Two independent timestamps, because the two passes read different ones: last_accessed_at is
    // the recency keep_versions ranks on, last_used is what the keep_days age filter compares to
    // its cutoff. A null lastUsed leaves the column NULL — a file this tenant has never
    // downloaded, which keep_days must treat as not-evictable.
    private async Task SeedFileAsync(
        string ecosystem, string name, string version, string filename, DateTimeOffset accessed,
        DateTimeOffset? lastUsed = null)
    {
        string blobKey = BlobKeys.Proxy(Convert.ToHexString(
            System.Security.Cryptography.SHA256.HashData(
                System.Text.Encoding.UTF8.GetBytes(name + version + filename))).ToLowerInvariant());
        await _blobs.PutAsync(blobKey, new MemoryStream(new byte[10]));

        var inserted = await new CacheArtifactRepository(_db).InsertAsync(new CacheArtifact
        {
            Id = Guid.NewGuid().ToString("D"),
            Ecosystem = ecosystem,
            Name = name,
            Version = version,
            Filename = filename,
            BlobKey = blobKey,
            ContentHash = "abc123",
            SizeBytes = 10,
            FirstCachedAt = accessed,
            LastAccessedAt = accessed,
        });

        var access = new TenantArtifactAccessRepository(_db);
        await access.UpsertAsync("o1", inserted.Id, accessed, TenantContentBinding.None);
        if (lastUsed is { } used)
        {
            await access.UpsertStateAsync("o1", inserted.Id, used);
        }
    }

    // The four files a Maven resolve caches for one version.
    private static readonly string[] MavenSuffixes = [".jar", ".pom", "-sources.jar", "-javadoc.jar"];

    private async Task SeedMavenVersionAsync(
        string name, string version, DateTimeOffset accessed, DateTimeOffset? lastUsed = null)
    {
        foreach (string suffix in MavenSuffixes)
        {
            await SeedFileAsync("maven", name, version, $"widget-{version}{suffix}", accessed, lastUsed);
        }
    }

    private async Task<List<string>> SurvivingVersionsAsync(string name)
    {
        await using var conn = await _db.OpenAsync();
        var rows = await conn.QueryAsync<string>(
            """
            SELECT DISTINCT ca.version
            FROM cache_artifact ca
            JOIN tenant_artifact_access taa ON taa.cache_artifact_id = ca.id
            WHERE taa.org_id = 'o1' AND ca.name = @name
            ORDER BY ca.version
            """,
            new { name });
        return rows.ToList();
    }

    private async Task<int> FileCountAsync(string name, string version)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.ExecuteScalarAsync<int>(
            """
            SELECT COUNT(*)
            FROM cache_artifact ca
            JOIN tenant_artifact_access taa ON taa.cache_artifact_id = ca.id
            WHERE taa.org_id = 'o1' AND ca.name = @name AND ca.version = @version
            """,
            new { name, version });
    }

    // The assertion that matters: no version survives in pieces. Every version still present keeps
    // its COMPLETE file set, and every evicted version left no row and no blob behind.
    private async Task AssertNoPartialVersionAsync(
        string name, IReadOnlyCollection<string> expectedSurvivors, IReadOnlyCollection<string> expectedEvicted)
    {
        Assert.Equal(expectedSurvivors.OrderBy(v => v, StringComparer.Ordinal), await SurvivingVersionsAsync(name));

        foreach (string version in expectedSurvivors)
        {
            Assert.Equal(MavenSuffixes.Length, await FileCountAsync(name, version));
            foreach (string suffix in MavenSuffixes)
            {
                string blobKey = BlobKeys.Proxy(Convert.ToHexString(
                    System.Security.Cryptography.SHA256.HashData(
                        System.Text.Encoding.UTF8.GetBytes(name + version + $"widget-{version}{suffix}"))).ToLowerInvariant());
                Assert.True(await _blobs.ExistsAsync(BlobKeys.StoreKey(blobKey)),
                    $"retained version {version} lost file {suffix}: a partial version resolves broken");
            }
        }

        foreach (string version in expectedEvicted)
        {
            Assert.Equal(0, await FileCountAsync(name, version));
        }
    }

    [Fact]
    public async Task KeepVersions_RetainsThatManyVersions_NotThatManyFiles()
    {
        var t = _clock.GetUtcNow();

        // Five Maven versions × 4 files = 20 cache_artifact rows. Capping rows at 5 would retain
        // roughly one real version; the cap counts versions, so it retains five.
        await SeedMavenVersionAsync("com.acme:widget", "1.0.0", t.AddDays(-50));
        await SeedMavenVersionAsync("com.acme:widget", "2.0.0", t.AddDays(-40));
        await SeedMavenVersionAsync("com.acme:widget", "3.0.0", t.AddDays(-30));
        await SeedMavenVersionAsync("com.acme:widget", "4.0.0", t.AddDays(-20));
        await SeedMavenVersionAsync("com.acme:widget", "5.0.0", t.AddDays(-10));

        var svc = Build();
        await using var conn = await _db.OpenAsync();
        await svc.EnforceVersionLimitAsync(conn, "o1", keepVersions: 5, default);

        await AssertNoPartialVersionAsync(
            "com.acme:widget",
            expectedSurvivors: ["1.0.0", "2.0.0", "3.0.0", "4.0.0", "5.0.0"],
            expectedEvicted: []);
    }

    // The mixed pass: in ONE call, some versions are evicted and some retained. The cut falls
    // between versions, never inside one.
    [Fact]
    public async Task MixedPass_EvictsOldVersionsWholly_AndRetainsNewVersionsComplete()
    {
        var t = _clock.GetUtcNow();

        await SeedMavenVersionAsync("com.acme:widget", "1.0.0", t.AddDays(-50)); // evicted
        await SeedMavenVersionAsync("com.acme:widget", "2.0.0", t.AddDays(-40)); // evicted
        await SeedMavenVersionAsync("com.acme:widget", "3.0.0", t.AddDays(-30)); // evicted
        await SeedMavenVersionAsync("com.acme:widget", "4.0.0", t.AddDays(-20)); // kept
        await SeedMavenVersionAsync("com.acme:widget", "5.0.0", t.AddDays(-10)); // kept

        var svc = Build();
        await using var conn = await _db.OpenAsync();
        await svc.EnforceVersionLimitAsync(conn, "o1", keepVersions: 2, default);

        await AssertNoPartialVersionAsync(
            "com.acme:widget",
            expectedSurvivors: ["4.0.0", "5.0.0"],
            expectedEvicted: ["1.0.0", "2.0.0", "3.0.0"]);
    }

    // A version's files are not all touched at the same instant: a resolve fetches the .pom, then
    // the .jar later. Ranking by row recency would split such a version across the cut — keeping
    // the recently touched file and evicting the rest.
    [Fact]
    public async Task VersionWithFilesAccessedAtDifferentTimes_IsNeverSplitAcrossTheCut()
    {
        var t = _clock.GetUtcNow();

        // 1.0.0's .jar was touched most recently of all, but the version as a whole is the oldest.
        await SeedFileAsync("maven", "com.acme:split", "1.0.0", "widget-1.0.0.pom", t.AddDays(-50));
        await SeedFileAsync("maven", "com.acme:split", "1.0.0", "widget-1.0.0.jar", t.AddDays(-1));
        await SeedFileAsync("maven", "com.acme:split", "2.0.0", "widget-2.0.0.pom", t.AddDays(-10));
        await SeedFileAsync("maven", "com.acme:split", "2.0.0", "widget-2.0.0.jar", t.AddDays(-10));

        var svc = Build();
        await using var conn = await _db.OpenAsync();
        await svc.EnforceVersionLimitAsync(conn, "o1", keepVersions: 1, default);

        // A version's recency is its most recently accessed file, so 1.0.0 (touched a day ago)
        // outranks 2.0.0 — and it is retained COMPLETE, .pom included, not just its fresh .jar.
        Assert.Equal(["1.0.0"], await SurvivingVersionsAsync("com.acme:split"));
        Assert.Equal(2, await FileCountAsync("com.acme:split", "1.0.0"));
        Assert.Equal(0, await FileCountAsync("com.acme:split", "2.0.0"));
    }

    [Fact]
    public async Task EvictionIsScopedPerName_AndDoesNotBorrowAnotherNamesBudget()
    {
        var t = _clock.GetUtcNow();

        await SeedMavenVersionAsync("com.acme:alpha", "1.0.0", t.AddDays(-50));
        await SeedMavenVersionAsync("com.acme:alpha", "2.0.0", t.AddDays(-10));
        await SeedMavenVersionAsync("com.acme:beta", "1.0.0", t.AddDays(-40));
        await SeedMavenVersionAsync("com.acme:beta", "2.0.0", t.AddDays(-5));

        var svc = Build();
        await using var conn = await _db.OpenAsync();
        await svc.EnforceVersionLimitAsync(conn, "o1", keepVersions: 1, default);

        await AssertNoPartialVersionAsync("com.acme:alpha", ["2.0.0"], ["1.0.0"]);
        await AssertNoPartialVersionAsync("com.acme:beta", ["2.0.0"], ["1.0.0"]);
    }

    // Shutdown lands mid-eviction — the realistic interruption, since the pass honours the
    // shutdown token. The checkpoint is the version boundary, so a version whose eviction has
    // begun runs to completion; a checkpoint between files would leave the version in pieces,
    // which is the corruption the keep-set is shaped to prevent.
    [Fact]
    public async Task CancelledPartWayThroughAVersion_StillEvictsThatVersionWhole()
    {
        var t = _clock.GetUtcNow();

        await SeedMavenVersionAsync("com.acme:widget", "1.0.0", t.AddDays(-50)); // evicted
        await SeedMavenVersionAsync("com.acme:widget", "2.0.0", t.AddDays(-40)); // evicted
        await SeedMavenVersionAsync("com.acme:widget", "3.0.0", t.AddDays(-10)); // kept

        // Cancellation fires the moment the pass deletes its first blob — i.e. part way through
        // the first evicted version, with its remaining files still present.
        using var cts = new CancellationTokenSource();
        var blobs = new CancelOnFirstDeleteBlobStore(_blobs, cts);

        var cfg = new ConfigurationBuilder().Build();
        var svc = new RetentionService(new RetentionService.Dependencies(
            _db, blobs, new JwtRevocationRepository(_db, time: _clock),
            new InviteRepository(_db, _clock), new SamlConfigRepository(_db, _clock), new TrustedDeviceService(_db, _clock, cfg),
            cfg, new AirGapMode(cfg), NullLogger<RetentionService>.Instance, _clock,
            new Dependably.Infrastructure.Redis.InProcessDistributedLock(_clock),
            new Dependably.Protocol.OciOrphanBlobDeleter(
                _db, new Dependably.Storage.TieredBlobStorage(_blobs, _blobs),
                new Dependably.Protocol.OciBlobKeyLock()),
            new Dependably.Infrastructure.Mail.EmailOutboxRepository(_db, _clock),
            new Dependably.Infrastructure.Mail.EmailOutboxPolicy(cfg)));

        await using var conn = await _db.OpenAsync();
        await svc.EnforceVersionLimitAsync(conn, "o1", keepVersions: 1, cts.Token);

        Assert.True(blobs.DeleteCount > 0, "the pass must have started evicting for this to test anything");

        // Every version still present is COMPLETE: the interrupted version either finished
        // evicting (no rows) or was never started (all 4 files) — never 1 of 4.
        foreach (string version in await SurvivingVersionsAsync("com.acme:widget"))
        {
            Assert.Equal(MavenSuffixes.Length, await FileCountAsync("com.acme:widget", version));
        }
    }

    // ── keep_days (EvictStaleBlobsAsync): the same rule via the age filter ───

    // The bug: last_used is per FILE, so a Maven version whose .jar is re-read on every build
    // while its .pom is not would have the .pom aged out from under it — a version that still
    // lists and 404s on resolve.
    [Fact]
    public async Task KeepDays_VersionWhoseJarIsStillUsed_KeepsItsPomToo()
    {
        var t = _clock.GetUtcNow();

        // One version, four files. The .jar was downloaded yesterday; the other three not in 50
        // days. Against a 30-day cutoff a per-row filter evicts three of four files.
        await SeedFileAsync("maven", "com.acme:widget", "1.0.0", "widget-1.0.0.pom", t.AddDays(-50), t.AddDays(-50));
        await SeedFileAsync("maven", "com.acme:widget", "1.0.0", "widget-1.0.0.jar", t.AddDays(-1), t.AddDays(-1));
        await SeedFileAsync("maven", "com.acme:widget", "1.0.0", "widget-1.0.0-sources.jar", t.AddDays(-50), t.AddDays(-50));
        await SeedFileAsync("maven", "com.acme:widget", "1.0.0", "widget-1.0.0-javadoc.jar", t.AddDays(-50), t.AddDays(-50));

        var svc = Build();
        await using var conn = await _db.OpenAsync();
        await svc.EvictStaleBlobsAsync(conn, "o1", keepDays: 30, default);

        // The version is in use, so it is retained COMPLETE — not reduced to the one fresh file.
        Assert.Equal(["1.0.0"], await SurvivingVersionsAsync("com.acme:widget"));
        Assert.Equal(MavenSuffixes.Length, await FileCountAsync("com.acme:widget", "1.0.0"));
    }

    // The mixed pass the ticket asks for: in ONE call some versions age out and some stay, and no
    // version survives in pieces either way.
    [Fact]
    public async Task KeepDays_MixedPass_EvictsWhollyStaleVersions_AndRetainsTheRestComplete()
    {
        var t = _clock.GetUtcNow();

        // Wholly stale — every file last used 50 days ago.
        await SeedMavenVersionAsync("com.acme:widget", "1.0.0", t.AddDays(-50), t.AddDays(-50));
        await SeedMavenVersionAsync("com.acme:widget", "2.0.0", t.AddDays(-50), t.AddDays(-50));
        // Wholly fresh.
        await SeedMavenVersionAsync("com.acme:widget", "4.0.0", t.AddDays(-1), t.AddDays(-1));
        // Mixed: one fresh file, three stale — the shape a per-row filter shreds.
        await SeedFileAsync("maven", "com.acme:widget", "3.0.0", "widget-3.0.0.pom", t.AddDays(-50), t.AddDays(-50));
        await SeedFileAsync("maven", "com.acme:widget", "3.0.0", "widget-3.0.0.jar", t.AddDays(-1), t.AddDays(-1));
        await SeedFileAsync("maven", "com.acme:widget", "3.0.0", "widget-3.0.0-sources.jar", t.AddDays(-50), t.AddDays(-50));
        await SeedFileAsync("maven", "com.acme:widget", "3.0.0", "widget-3.0.0-javadoc.jar", t.AddDays(-50), t.AddDays(-50));

        var svc = Build();
        await using var conn = await _db.OpenAsync();
        await svc.EvictStaleBlobsAsync(conn, "o1", keepDays: 30, default);

        await AssertNoPartialVersionAsync(
            "com.acme:widget",
            expectedSurvivors: ["3.0.0", "4.0.0"],
            expectedEvicted: ["1.0.0", "2.0.0"]);
    }

    // A NULL last_used means this tenant has never downloaded the file — the per-row filter's
    // `last_used IS NOT NULL` never evicted those, and grouping must not start evicting them by
    // taking MAX over the non-null rows and finding the group stale.
    [Fact]
    public async Task KeepDays_VersionHoldingANeverDownloadedFile_IsNotEvicted()
    {
        var t = _clock.GetUtcNow();

        await SeedFileAsync("maven", "com.acme:widget", "1.0.0", "widget-1.0.0.pom", t.AddDays(-50), t.AddDays(-50));
        await SeedFileAsync("maven", "com.acme:widget", "1.0.0", "widget-1.0.0.jar", t.AddDays(-50), lastUsed: null);

        var svc = Build();
        await using var conn = await _db.OpenAsync();
        await svc.EvictStaleBlobsAsync(conn, "o1", keepDays: 30, default);

        Assert.Equal(["1.0.0"], await SurvivingVersionsAsync("com.acme:widget"));
        Assert.Equal(2, await FileCountAsync("com.acme:widget", "1.0.0"));
    }

    // Shutdown lands mid-eviction on the age pass too. The checkpoint is the version boundary, so
    // a version whose eviction has begun runs to completion rather than being left in pieces.
    [Fact]
    public async Task KeepDays_CancelledPartWayThroughAVersion_StillEvictsThatVersionWhole()
    {
        var t = _clock.GetUtcNow();

        await SeedMavenVersionAsync("com.acme:widget", "1.0.0", t.AddDays(-50), t.AddDays(-50));
        await SeedMavenVersionAsync("com.acme:widget", "2.0.0", t.AddDays(-50), t.AddDays(-50));
        await SeedMavenVersionAsync("com.acme:widget", "3.0.0", t.AddDays(-1), t.AddDays(-1));

        using var cts = new CancellationTokenSource();
        var blobs = new CancelOnFirstDeleteBlobStore(_blobs, cts);

        var cfg = new ConfigurationBuilder().Build();
        var svc = new RetentionService(new RetentionService.Dependencies(
            _db, blobs, new JwtRevocationRepository(_db, time: _clock),
            new InviteRepository(_db, _clock), new SamlConfigRepository(_db, _clock), new TrustedDeviceService(_db, _clock, cfg),
            cfg, new AirGapMode(cfg), NullLogger<RetentionService>.Instance, _clock,
            new Dependably.Infrastructure.Redis.InProcessDistributedLock(_clock),
            new Dependably.Protocol.OciOrphanBlobDeleter(
                _db, new Dependably.Storage.TieredBlobStorage(_blobs, _blobs),
                new Dependably.Protocol.OciBlobKeyLock()),
            new Dependably.Infrastructure.Mail.EmailOutboxRepository(_db, _clock),
            new Dependably.Infrastructure.Mail.EmailOutboxPolicy(cfg)));

        await using var conn = await _db.OpenAsync();
        await svc.EvictStaleBlobsAsync(conn, "o1", keepDays: 30, cts.Token);

        Assert.True(blobs.DeleteCount > 0, "the pass must have started evicting for this to test anything");

        foreach (string version in await SurvivingVersionsAsync("com.acme:widget"))
        {
            Assert.Equal(MavenSuffixes.Length, await FileCountAsync("com.acme:widget", version));
        }
    }

    // Cancels the token on the first blob delete, so the shutdown lands between two files of one
    // version. Delegates everything else to the real in-memory store.
    private sealed class CancelOnFirstDeleteBlobStore : IBlobStore
    {
        private readonly IBlobStore _inner;
        private readonly CancellationTokenSource _cts;

        public int DeleteCount { get; private set; }

        public CancelOnFirstDeleteBlobStore(IBlobStore inner, CancellationTokenSource cts)
        {
            _inner = inner;
            _cts = cts;
        }

        public async Task DeleteAsync(string key, CancellationToken ct = default)
        {
            await _inner.DeleteAsync(key, ct);
            DeleteCount++;
            await _cts.CancelAsync();
        }

        public Task PutAsync(string key, Stream data, CancellationToken ct = default) => _inner.PutAsync(key, data, ct);
        public Task<Stream?> GetAsync(string key, CancellationToken ct = default) => _inner.GetAsync(key, ct);
        public Task<bool> ExistsAsync(string key, CancellationToken ct = default) => _inner.ExistsAsync(key, ct);
        public Task<long> GetTotalSizeAsync(CancellationToken ct = default) => _inner.GetTotalSizeAsync(ct);
        public Task<RangedStream?> GetRangeAsync(string key, long from, long to, CancellationToken ct = default)
            => _inner.GetRangeAsync(key, from, to, ct);
        public IAsyncEnumerable<BlobInfo> ListAsync(string prefix, CancellationToken ct = default)
            => _inner.ListAsync(prefix, ct);
    }
}
