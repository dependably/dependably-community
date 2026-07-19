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
            new AirGapMode(cfg),
            NullLogger<OrphanBlobReconcilerService>.Instance,
            _clock,
            new Dependably.Infrastructure.Redis.InProcessDistributedLock(_clock));
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

    /// <summary>
    /// Creates a package + package_versions row whose blob_key is the version's PRIMARY artefact
    /// (the first file published), plants that blob, and returns the version id so the caller can
    /// hang secondary-file rows off it. This is the exact shape Maven and multi-file PyPI produce:
    /// one shared package_versions row per version, with the sibling files' keys living only in
    /// maven_version_files / package_version_files.
    /// </summary>
    private async Task<string> SeedPrimaryArtifactAsync(
        string packageId, string ecosystem, string purlName, string version,
        string primaryBlobKey, DateTimeOffset lastModified)
    {
        string versionId = Guid.NewGuid().ToString("N");
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) " +
            "VALUES (@id, 'o1', @eco, @name, @name, 0)",
            new { id = packageId, eco = ecosystem, name = purlName });
        await conn.ExecuteAsync(
            "INSERT INTO package_versions (id, package_id, version, purl, blob_key, size_bytes, origin) " +
            "VALUES (@id, @pkgId, @v, @p, @k, 4, 'uploaded')",
            new
            {
                id = versionId,
                pkgId = packageId,
                v = version,
                p = $"pkg:{ecosystem}/{purlName}@{version}",
                k = primaryBlobKey,
            });
        _registry.SeedWithLastModified(primaryBlobKey, new byte[] { 1, 2, 3, 4 }, lastModified);
        return versionId;
    }

    /// <summary>Secondary Maven file (.pom, sources jar, …): blob_key lives ONLY in maven_version_files.</summary>
    private async Task SeedMavenSecondaryFileAsync(
        string versionId, string filename, string extension, string blobKey,
        byte[] bytes, DateTimeOffset lastModified)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO maven_version_files " +
            "(id, package_version_id, filename, extension, blob_key, size_bytes, origin, owner_kind) " +
            "VALUES (@id, @pvId, @filename, @ext, @k, @s, 'uploaded', 'package_version')",
            new
            {
                id = Guid.NewGuid().ToString("N"),
                pvId = versionId,
                filename,
                ext = extension,
                k = blobKey,
                s = bytes.Length,
            });
        _registry.SeedWithLastModified(blobKey, bytes, lastModified);
    }

    /// <summary>Secondary PyPI distribution file (sdist beside a wheel): blob_key lives ONLY in package_version_files.</summary>
    private async Task SeedPypiSecondaryFileAsync(
        string versionId, string filename, string blobKey, byte[] bytes, DateTimeOffset lastModified)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO package_version_files " +
            "(id, package_version_id, org_id, filename, blob_key, size_bytes) " +
            "VALUES (@id, @pvId, 'o1', @filename, @k, @s)",
            new
            {
                id = Guid.NewGuid().ToString("N"),
                pvId = versionId,
                filename,
                k = blobKey,
                s = bytes.Length,
            });
        _registry.SeedWithLastModified(blobKey, bytes, lastModified);
    }

    /// <summary>Symbol package: blob_key lives ONLY in nuget_symbol_index.snupkg_blob_key.</summary>
    private async Task SeedNuGetSymbolAsync(
        string versionId, string snupkgBlobKey, byte[] bytes, DateTimeOffset lastModified)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO nuget_symbol_index " +
            "(id, org_id, package_version_id, pdb_filename, ssqp_key, snupkg_blob_key, entry_path) " +
            "VALUES (@id, 'o1', @pvId, 'acme.pdb', @ssqp, @k, 'lib/net10.0/acme.pdb')",
            new
            {
                id = Guid.NewGuid().ToString("N"),
                pvId = versionId,
                ssqp = Guid.NewGuid().ToString("N") + "ffffffff",
                k = snupkgBlobKey,
            });
        _registry.SeedWithLastModified(snupkgBlobKey, bytes, lastModified);
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
    public async Task Disabled_ByDenylist_SkipsSweep_OrphanSurvives()
    {
        // Wiring test: with orphan-reconciler in DISABLE_BACKGROUND_JOBS the sweep must be a
        // no-op, so an over-grace orphan survives (proves the IsJobDisabled guard fires).
        string orphanKey = BlobKeys.Hosted("o1", "npm", "ghost", "2.0.0", "ghost-2.0.0.tgz");
        _registry.SeedWithLastModified(orphanKey, new byte[] { 9 }, _clock.GetUtcNow().AddMinutes(-10));

        var cfg = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ORPHAN_RECONCILE_GRACE_MINUTES"] = "1",
                ["DISABLE_BACKGROUND_JOBS"] = "orphan-reconciler",
            })
            .Build();
        var sut = new OrphanBlobReconcilerService(
            new TieredBlobStorage(_cache, _registry), new PackageRepository(_db), cfg,
            new AirGapMode(cfg), NullLogger<OrphanBlobReconcilerService>.Instance, _clock,
            new Dependably.Infrastructure.Redis.InProcessDistributedLock(_clock));

        var summary = await sut.RunOnceAsync();

        Assert.Equal(0, summary.OrphansDeleted);
        Assert.True(await _registry.ExistsAsync(orphanKey));
    }

    [Fact]
    public async Task EdgeMode_SkipsSweep_OrphanSurvives()
    {
        // orphan-reconciler is not in the edge allowlist, so an edge node force-disables it.
        string orphanKey = BlobKeys.Hosted("o1", "npm", "ghost", "3.0.0", "ghost-3.0.0.tgz");
        _registry.SeedWithLastModified(orphanKey, new byte[] { 9 }, _clock.GetUtcNow().AddMinutes(-10));

        var cfg = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ORPHAN_RECONCILE_GRACE_MINUTES"] = "1",
                ["DEPLOYMENT_MODE"] = "edge",
            })
            .Build();
        var sut = new OrphanBlobReconcilerService(
            new TieredBlobStorage(_cache, _registry), new PackageRepository(_db), cfg,
            new AirGapMode(cfg), NullLogger<OrphanBlobReconcilerService>.Instance, _clock,
            new Dependably.Infrastructure.Redis.InProcessDistributedLock(_clock));

        var summary = await sut.RunOnceAsync();

        Assert.Equal(0, summary.OrphansDeleted);
        Assert.True(await _registry.ExistsAsync(orphanKey));
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
            new AirGapMode(cfg),
            NullLogger<OrphanBlobReconcilerService>.Instance,
            _clock,
            new Dependably.Infrastructure.Redis.InProcessDistributedLock(_clock));

        var summary = await sut.RunOnceAsync();

        Assert.Equal(1, summary.OrphansDeleted);    // the good one
        Assert.Equal(1, summary.DeletionFailures);  // the poison one
        Assert.True(await _registry.ExistsAsync(poisonKey));  // failed delete; still there
        Assert.False(await _registry.ExistsAsync(goodKey));   // succeeded
    }

    [Fact]
    public async Task MavenSidecar_ReferencedOnlyFromMavenVersionFiles_IsNotDeleted()
    {
        // A Maven version shares ONE package_versions row across all its files; only the first
        // file published lands its key there. The .pom (and sources/javadoc jars) are referenced
        // solely from maven_version_files. A referenced set built from package_versions alone
        // classifies them as orphans and deletes them — a missing .pom breaks resolution of the
        // whole artefact.
        var old = _clock.GetUtcNow().AddMinutes(-10);
        string jarKey = BlobKeys.Hosted("o1", "maven", "com/acme/widget", "1.0.0", "widget-1.0.0.jar");
        string pomKey = BlobKeys.Hosted("o1", "maven", "com/acme/widget", "1.0.0", "widget-1.0.0.pom");
        string sourcesKey = BlobKeys.Hosted("o1", "maven", "com/acme/widget", "1.0.0", "widget-1.0.0-sources.jar");

        string versionId = await SeedPrimaryArtifactAsync(
            "pkg-maven", "maven", "com.acme:widget", "1.0.0", jarKey, old);
        await SeedMavenSecondaryFileAsync(versionId, "widget-1.0.0.pom", "pom", pomKey, new byte[] { 5, 5 }, old);
        await SeedMavenSecondaryFileAsync(versionId, "widget-1.0.0-sources.jar", "jar", sourcesKey, new byte[] { 6 }, old);

        var summary = await _sut.RunOnceAsync();

        Assert.Equal(0, summary.OrphansDeleted);
        Assert.True(await _registry.ExistsAsync(jarKey), "primary jar must survive");
        Assert.True(await _registry.ExistsAsync(pomKey), ".pom is referenced by maven_version_files and must survive");
        Assert.True(await _registry.ExistsAsync(sourcesKey), "sources jar is referenced by maven_version_files and must survive");
    }

    [Fact]
    public async Task PypiSecondaryFile_ReferencedOnlyFromPackageVersionFiles_IsNotDeleted()
    {
        // Multi-file PyPI: the wheel published first owns package_versions.blob_key; an sdist
        // uploaded afterwards for the same release gets only a package_version_files row. The
        // sdist blob must not be swept.
        var old = _clock.GetUtcNow().AddMinutes(-10);
        string wheelKey = BlobKeys.Hosted("o1", "pypi", "widget", "1.0.0", "widget-1.0.0-py3-none-any.whl");
        string sdistKey = BlobKeys.Hosted("o1", "pypi", "widget", "1.0.0", "widget-1.0.0.tar.gz");

        string versionId = await SeedPrimaryArtifactAsync(
            "pkg-pypi", "pypi", "widget", "1.0.0", wheelKey, old);
        await SeedPypiSecondaryFileAsync(versionId, "widget-1.0.0.tar.gz", sdistKey, new byte[] { 7, 7, 7 }, old);

        var summary = await _sut.RunOnceAsync();

        Assert.Equal(0, summary.OrphansDeleted);
        Assert.True(await _registry.ExistsAsync(wheelKey), "wheel must survive");
        Assert.True(await _registry.ExistsAsync(sdistKey), "sdist is referenced by package_version_files and must survive");
    }

    [Fact]
    public async Task NuGetSnupkg_ReferencedOnlyFromSymbolIndex_IsNotDeleted()
    {
        // The symbol-push path gives the .snupkg its own package_versions row, so today the key
        // is also reachable there. This test seeds the .snupkg key ONLY in nuget_symbol_index —
        // the shape the sweep must survive if that duplication ever stops holding — pinning
        // nuget_symbol_index as a first-class arm of the referenced set rather than a coincidence.
        var old = _clock.GetUtcNow().AddMinutes(-10);
        string nupkgKey = BlobKeys.Hosted("o1", "nuget", "acme.lib", "1.0.0", "acme.lib.1.0.0.nupkg");
        string snupkgKey = BlobKeys.Hosted("o1", "nuget", "acme.lib", "1.0.0", "acme.lib.1.0.0.snupkg");

        string versionId = await SeedPrimaryArtifactAsync(
            "pkg-nuget", "nuget", "acme.lib", "1.0.0", nupkgKey, old);
        await SeedNuGetSymbolAsync(versionId, snupkgKey, new byte[] { 8, 8 }, old);

        var summary = await _sut.RunOnceAsync();

        Assert.Equal(0, summary.OrphansDeleted);
        Assert.True(await _registry.ExistsAsync(nupkgKey), ".nupkg must survive");
        Assert.True(await _registry.ExistsAsync(snupkgKey), ".snupkg is referenced by nuget_symbol_index and must survive");
    }

    [Fact]
    public async Task MixedSweep_SecondaryFileTablesSurvive_TrueOrphanStillDeleted()
    {
        // Partial-failure shape: one pass, every reference class plus a genuine orphan. Proves the
        // union widened the referenced set without neutering the sweep into a no-op — the orphan
        // (a hosted blob no table references) is still reaped in the same pass that spares the
        // Maven .pom, the PyPI sdist, and the .snupkg.
        var old = _clock.GetUtcNow().AddMinutes(-10);

        string jarKey = BlobKeys.Hosted("o1", "maven", "com/acme/widget", "2.0.0", "widget-2.0.0.jar");
        string pomKey = BlobKeys.Hosted("o1", "maven", "com/acme/widget", "2.0.0", "widget-2.0.0.pom");
        string mavenVersionId = await SeedPrimaryArtifactAsync(
            "pkg-maven2", "maven", "com.acme:widget", "2.0.0", jarKey, old);
        await SeedMavenSecondaryFileAsync(mavenVersionId, "widget-2.0.0.pom", "pom", pomKey, new byte[] { 5, 5 }, old);

        string wheelKey = BlobKeys.Hosted("o1", "pypi", "gadget", "2.0.0", "gadget-2.0.0-py3-none-any.whl");
        string sdistKey = BlobKeys.Hosted("o1", "pypi", "gadget", "2.0.0", "gadget-2.0.0.tar.gz");
        string pypiVersionId = await SeedPrimaryArtifactAsync(
            "pkg-pypi2", "pypi", "gadget", "2.0.0", wheelKey, old);
        await SeedPypiSecondaryFileAsync(pypiVersionId, "gadget-2.0.0.tar.gz", sdistKey, new byte[] { 7, 7, 7 }, old);

        string nupkgKey = BlobKeys.Hosted("o1", "nuget", "acme.tool", "2.0.0", "acme.tool.2.0.0.nupkg");
        string snupkgKey = BlobKeys.Hosted("o1", "nuget", "acme.tool", "2.0.0", "acme.tool.2.0.0.snupkg");
        string nugetVersionId = await SeedPrimaryArtifactAsync(
            "pkg-nuget2", "nuget", "acme.tool", "2.0.0", nupkgKey, old);
        await SeedNuGetSymbolAsync(nugetVersionId, snupkgKey, new byte[] { 8, 8 }, old);

        // Referenced by nothing at all — the SIGKILL orphan the sweep exists to reap.
        string orphanKey = BlobKeys.Hosted("o1", "maven", "com/acme/ghost", "9.9.9", "ghost-9.9.9.pom");
        _registry.SeedWithLastModified(orphanKey, new byte[] { 9, 9, 9, 9 }, old);

        var summary = await _sut.RunOnceAsync();

        Assert.Equal(1, summary.OrphansDeleted);
        Assert.Equal(4, summary.BytesFreed);
        Assert.False(await _registry.ExistsAsync(orphanKey), "true orphan must still be deleted");
        Assert.True(await _registry.ExistsAsync(jarKey));
        Assert.True(await _registry.ExistsAsync(pomKey), "Maven .pom must survive");
        Assert.True(await _registry.ExistsAsync(wheelKey));
        Assert.True(await _registry.ExistsAsync(sdistKey), "PyPI sdist must survive");
        Assert.True(await _registry.ExistsAsync(nupkgKey));
        Assert.True(await _registry.ExistsAsync(snupkgKey), ".snupkg must survive");
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
