using Dapper;
using Dependably.Infrastructure;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit.Infrastructure;

[Trait("Category", "Unit")]
public sealed class OrphanBlobReconcilerServiceTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly InMemoryBlobStore _registry = new();
    private readonly InMemoryBlobStore _cache = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen();
    private OrphanBlobReconcilerService _sut = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme')");
        await conn.ExecuteAsync(
            "INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) " +
            "VALUES ('pkg1', 'o1', 'npm', 'acme', 'acme', 0)");

        var cfg = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                // Tiny grace so we can plant "old" blobs without sleeping in tests.
                ["ORPHAN_RECONCILE_GRACE_MINUTES"] = "1",
            })
            .Build();
        var tiered = new TieredBlobStorage(_cache, _registry);
        _sut = new OrphanBlobReconcilerService(tiered, new PackageRepository(_db), cfg,
            NullLogger<OrphanBlobReconcilerService>.Instance,
            _clock);
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    /// <summary>Plant a referenced version row + its blob, both with matching key.</summary>
    private async Task SeedReferencedAsync(string version, string blobKey, byte[] bytes, DateTimeOffset lastModified)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO package_versions (id, package_id, version, purl, blob_key, size_bytes) " +
            "VALUES (@id, 'pkg1', @v, @p, @k, @s)",
            new { id = Guid.NewGuid().ToString("N"), v = version, p = $"pkg:npm/acme@{version}", k = blobKey, s = bytes.Length });
        _registry.SeedWithLastModified(blobKey, bytes, lastModified);
    }

    [Fact]
    public async Task ReferencedBlobs_AreLeftAlone()
    {
        // The whole point: a hosted blob with a matching package_versions row must survive
        // the sweep regardless of how old it is.
        var ancient = _clock.GetUtcNow().AddDays(-365);
        await SeedReferencedAsync("1.0.0",
            BlobKeys.Hosted("o1", "npm", "acme", "1.0.0", "acme-1.0.0.tgz"),
            new byte[] { 1, 2, 3 }, ancient);

        var summary = await _sut.RunOnceAsync();

        Assert.Equal(0, summary.OrphansDeleted);
        Assert.True(await _registry.ExistsAsync(BlobKeys.Hosted("o1", "npm", "acme", "1.0.0", "acme-1.0.0.tgz")));
    }

    [Fact]
    public async Task OrphanBlob_OlderThanGrace_IsDeleted()
    {
        // Unreferenced hosted blob with mtime safely outside the 1-minute grace window
        // must be reaped on the next pass.
        string orphanKey = BlobKeys.Hosted("o1", "npm", "ghost", "1.0.0", "ghost-1.0.0.tgz");
        _registry.SeedWithLastModified(orphanKey, new byte[] { 9, 9, 9 },
            _clock.GetUtcNow().AddMinutes(-10));

        var summary = await _sut.RunOnceAsync();

        Assert.Equal(1, summary.OrphansDeleted);
        Assert.Equal(3, summary.BytesFreed);
        Assert.False(await _registry.ExistsAsync(orphanKey));
    }

    [Fact]
    public async Task OrphanBlob_InsideGraceWindow_IsLeftAlone()
    {
        // A blob whose mtime is more recent than (now - grace) could be from a publish
        // still committing its row. Skip it; the next pass will catch it if it's still
        // unreferenced.
        string freshOrphanKey = BlobKeys.Hosted("o1", "npm", "wip", "1.0.0", "wip-1.0.0.tgz");
        _registry.SeedWithLastModified(freshOrphanKey, new byte[] { 7, 7, 7 },
            _clock.GetUtcNow());  // brand new — well inside the 1-minute grace

        var summary = await _sut.RunOnceAsync();

        Assert.Equal(0, summary.OrphansDeleted);
        Assert.True(await _registry.ExistsAsync(freshOrphanKey));
    }

    [Fact]
    public async Task CacheTierBlobs_AreNotTouched()
    {
        // Cache eviction is a separate service; this reconciler must never touch
        // proxy/ keys even when they're unreferenced. The "hosted/" prefix gate enforces it.
        _cache.SeedWithLastModified("proxy/deadbeef", new byte[] { 1 },
            _clock.GetUtcNow().AddDays(-365));

        var summary = await _sut.RunOnceAsync();

        Assert.Equal(0, summary.OrphansDeleted);
        Assert.True(await _cache.ExistsAsync("proxy/deadbeef"));
    }

    [Fact]
    public async Task MixedSet_ReferencedAreKept_OrphansAreDeleted_FreshOrphansSurvive()
    {
        // End-to-end: one of each kind in the same pass.
        string refKey = BlobKeys.Hosted("o1", "npm", "keep", "1.0.0", "keep-1.0.0.tgz");
        await SeedReferencedAsync("1.0.0", refKey, new byte[] { 1, 2 },
            _clock.GetUtcNow().AddDays(-1));

        string oldOrphan = BlobKeys.Hosted("o1", "npm", "old", "1.0.0", "old-1.0.0.tgz");
        _registry.SeedWithLastModified(oldOrphan, new byte[] { 3, 4, 5 },
            _clock.GetUtcNow().AddMinutes(-10));

        string freshOrphan = BlobKeys.Hosted("o1", "npm", "fresh", "1.0.0", "fresh-1.0.0.tgz");
        _registry.SeedWithLastModified(freshOrphan, new byte[] { 6 },
            _clock.GetUtcNow());

        var summary = await _sut.RunOnceAsync();

        Assert.Equal(1, summary.OrphansDeleted);
        Assert.Equal(3, summary.BytesFreed);
        Assert.True(await _registry.ExistsAsync(refKey), "referenced blob must survive");
        Assert.False(await _registry.ExistsAsync(oldOrphan), "old orphan must be deleted");
        Assert.True(await _registry.ExistsAsync(freshOrphan), "in-grace orphan must survive");
    }

    [Fact]
    public async Task DeleteFailure_IsCountedButDoesNotAbortPass()
    {
        // If one delete fails, the reconciler must keep going for the rest of the listing
        // and report the failure count. Simulate via a wrapper store that throws on a
        // specific key's DeleteAsync.
        string poisonKey = BlobKeys.Hosted("o1", "npm", "poison", "1.0.0", "poison-1.0.0.tgz");
        string goodKey = BlobKeys.Hosted("o1", "npm", "good", "1.0.0", "good-1.0.0.tgz");
        var oldTime = _clock.GetUtcNow().AddMinutes(-10);
        _registry.SeedWithLastModified(poisonKey, new byte[] { 1 }, oldTime);
        _registry.SeedWithLastModified(goodKey, new byte[] { 2 }, oldTime);

        var failing = new DeleteFailsForKeyStore(_registry, poisonKey);
        var tiered = new TieredBlobStorage(_cache, failing);
        var cfg = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            { ["ORPHAN_RECONCILE_GRACE_MINUTES"] = "1" })
            .Build();
        var sut = new OrphanBlobReconcilerService(tiered, new PackageRepository(_db), cfg,
            NullLogger<OrphanBlobReconcilerService>.Instance,
            _clock);

        var summary = await sut.RunOnceAsync();

        Assert.Equal(1, summary.OrphansDeleted);    // the good one
        Assert.Equal(1, summary.DeletionFailures);  // the poison one
        Assert.True(await _registry.ExistsAsync(poisonKey));  // failed delete; still there
        Assert.False(await _registry.ExistsAsync(goodKey));   // succeeded
    }

    /// <summary>
    /// Decorator that forwards every IBlobStore call except DeleteAsync, which throws when
    /// the key matches a configured value. Used to verify the reconciler tolerates partial
    /// delete failures without aborting the pass.
    /// </summary>
    private sealed class DeleteFailsForKeyStore : IBlobStore
    {
        private readonly IBlobStore _inner;
        private readonly string _failKey;
        public DeleteFailsForKeyStore(IBlobStore inner, string failKey)
        {
            _inner = inner;
            _failKey = failKey;
        }
        public Task PutAsync(string key, Stream data, CancellationToken ct = default)
            => _inner.PutAsync(key, data, ct);
        public Task<Stream?> GetAsync(string key, CancellationToken ct = default)
            => _inner.GetAsync(key, ct);
        public Task<RangedStream?> GetRangeAsync(string key, long from, long to, CancellationToken ct = default)
            => _inner.GetRangeAsync(key, from, to, ct);
        public Task<bool> ExistsAsync(string key, CancellationToken ct = default)
            => _inner.ExistsAsync(key, ct);
        public Task DeleteAsync(string key, CancellationToken ct = default)
            => key == _failKey
                ? throw new InvalidOperationException("simulated delete failure")
                : _inner.DeleteAsync(key, ct);
        public Task<long> GetTotalSizeAsync(CancellationToken ct = default)
            => _inner.GetTotalSizeAsync(ct);
        public IAsyncEnumerable<BlobInfo> ListAsync(string prefix, CancellationToken ct = default)
            => _inner.ListAsync(prefix, ct);
    }
}
