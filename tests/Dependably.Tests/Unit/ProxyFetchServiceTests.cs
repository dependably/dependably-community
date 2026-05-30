using Dapper;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using Xunit;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public sealed class ProxyFetchServiceTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly InMemoryBlobStore _blobs = new();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme')");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private ProxyFetchService Build(IBlobStore? blobOverride = null, IOsvSource? osvOverride = null)
    {
        var blobs = blobOverride ?? _blobs;
        var packages = new PackageRepository(_db);
        var audit = new AuditRepository(_db);
        var licenses = new LicenseRepository(_db);
        var vulns = new VulnerabilityRepository(_db);
        var cfg = new ConfigurationBuilder().Build();
        // Default OSV stub: returns no advisories so the block gate has nothing to act on.
        // Tests that need a vulnerable version pass their own stub via osvOverride.
        IOsvSource osv;
        if (osvOverride is not null)
        {
            osv = osvOverride;
        }
        else
        {
            osv = Substitute.For<IOsvSource>();
            osv.QueryAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
                .Returns(Task.FromResult(new List<OsvAdvisory>()));
            osv.QueryBatchAsync(Arg.Any<IReadOnlyList<string>>(), Arg.Any<CancellationToken>())
                .Returns(call => Task.FromResult(
                    call.Arg<IReadOnlyList<string>>().Select(_ => new List<OsvAdvisory>()).ToList()));
        }
        var scanner = new VulnerabilityScanService(_db, osv, vulns, audit, cfg,
            NullLogger<VulnerabilityScanService>.Instance);
        var proxyVersions = new ProxyVersionRecorder(packages, audit, licenses);
        var blockGate = new BlockGateService(vulns, audit);
        var cacheArtifact = new CacheArtifactRepository(_db);
        var tenantAccess = new TenantArtifactAccessRepository(_db);
        var cacheRecorder = new CacheAccessRecorder(cacheArtifact, tenantAccess,
            NullLogger<CacheAccessRecorder>.Instance);
        return new ProxyFetchService(cacheRecorder, proxyVersions, scanner, blockGate, packages, audit);
    }

    private static async Task<BlobHandle> SeedBlobAsync(InMemoryBlobStore blobs, byte[] bytes)
    {
        var sha = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes)).ToLowerInvariant();
        var key = BlobKeys.Proxy(sha);
        await blobs.PutAsync(key, new MemoryStream(bytes));
        return new BlobHandle(key, sha, bytes.LongLength,
            async ct => await blobs.GetAsync(key, ct)
                ?? throw new InvalidOperationException($"blob {key} vanished"));
    }

    [Fact]
    public async Task RecordAndScanAsync_clean_version_returns_Allowed_and_caches_blob()
    {
        var svc = Build();

        var bytes = "tarball-bytes"u8.ToArray();
        var blob = await SeedBlobAsync(_blobs, bytes);
        var result = await svc.RecordAndScanAsync(new ProxyFetchRequest(
            OrgId: "o1", Ecosystem: "npm",
            PackageName: "left-pad", PurlName: "left-pad",
            Version: "1.0.0", Purl: "pkg:npm/left-pad@1.0.0",
            File: "left-pad-1.0.0.tgz", Blob: blob,
            ExtractLicenses: null,
            UserId: null, ActorKind: null, SourceIp: "127.0.0.1",
            MaxOsvScoreTolerance: 10.0,
            CacheAccess: null));

        Assert.Equal(BlockDecision.Allowed, result.Decision);
        Assert.NotNull(result.VersionId);
        Assert.True(await _blobs.ExistsAsync(result.BlobKey));
    }

    [Fact]
    public async Task RecordAndScanAsync_vulnerable_version_over_tolerance_returns_Blocked()
    {
        // The miss-path gate every ecosystem's first-fetch relies on (incl. Maven, which has
        // no controller-level upstream harness): the synchronous scan links a high-score
        // advisory and BlockGateService refuses it on the very first fetch. Covers the
        // Blocked branch of RecordAndScanAsync that the clean-version test can't reach.
        var osv = Substitute.For<IOsvSource>();
        osv.QueryAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(new List<OsvAdvisory>
            {
                new("GHSA-test-0001", ["CVE-2024-0001"], "critical RCE", "CRITICAL",
                    CvssScore: 9.8, AffectedPackages: [], Published: null, Modified: null, IsHydrated: true),
            }));
        var svc = Build(osvOverride: osv);

        var bytes = "malicious-artifact"u8.ToArray();
        var blob = await SeedBlobAsync(_blobs, bytes);
        var result = await svc.RecordAndScanAsync(new ProxyFetchRequest(
            OrgId: "o1", Ecosystem: "maven",
            PackageName: "com.example:lib", PurlName: "com.example:lib",
            Version: "1.0.0", Purl: "pkg:maven/com.example/lib@1.0.0",
            File: "lib-1.0.0.jar", Blob: blob,
            ExtractLicenses: null,
            UserId: null, ActorKind: null, SourceIp: "127.0.0.1",
            MaxOsvScoreTolerance: 4.0,
            CacheAccess: null));

        Assert.Equal(BlockDecision.Blocked, result.Decision);
    }

    [Fact]
    public async Task RecordAndScanAsync_records_cache_access_when_provided()
    {
        var svc = Build();

        var bytes = "tarball"u8.ToArray();
        var blob = await SeedBlobAsync(_blobs, bytes);
        await svc.RecordAndScanAsync(new ProxyFetchRequest(
            OrgId: "o1", Ecosystem: "nuget",
            PackageName: "foo", PurlName: "foo",
            Version: "1.0.0", Purl: "pkg:nuget/foo@1.0.0",
            File: "foo.1.0.0.nupkg", Blob: blob,
            ExtractLicenses: null,
            UserId: null, ActorKind: null, SourceIp: null,
            MaxOsvScoreTolerance: 10.0,
            CacheAccess: new CacheAccess("o1", "nuget", "foo", "1.0.0", "foo.1.0.0.nupkg",
                Sha256: "", SizeBytes: 0, BlobKey: "",
                UpstreamUrl: "https://api.nuget.org/v3/flatcontainer/foo/1.0.0/foo.1.0.0.nupkg")));

        await using var conn = await _db.OpenAsync();
        var count = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM cache_artifact WHERE ecosystem = 'nuget'");
        Assert.Equal(1, count);
    }

    /// <summary>
    /// Per <c>feedback_test_partial_failure_scenarios</c>: in a fan-out where some
    /// extractions succeed and others fail with a transient IO error on blob open,
    /// every first-fetch row must still record, the failures must default to empty
    /// licenses, the successes must populate licenses, and no exception bubbles to
    /// the caller. Extraction runs after the response has been written, so an open
    /// failure here MUST NOT roll back the recording or fail the request.
    /// </summary>
    [Fact]
    public async Task RecordAndScanAsync_partial_license_extract_failures_record_all_versions()
    {
        // Real blob store wrapped so two specific reads throw an IOException on
        // the first GetAsync after PutAsync — this simulates a transient backend
        // hiccup during licence extraction.
        var inner = new InMemoryBlobStore();
        const int total = 5;
        const int failFrom = 3; // keys 4 and 5 fail (1-indexed)

        var coords = new List<(string PackageName, string Version, byte[] Bytes, BlobHandle Blob)>();
        for (var i = 0; i < total; i++)
        {
            var bytes = System.Text.Encoding.UTF8.GetBytes($"tar-{i}");
            var blob = await SeedBlobAsync(inner, bytes);
            coords.Add(($"pkg-{i}", $"1.0.{i}", bytes, blob));
        }

        // Wrap the blob store: throw on GetAsync for the last two coordinates.
        var failKeys = new HashSet<string>(coords.Skip(failFrom).Select(c => c.Blob.BlobKey));
        var wrapper = new FlakyBlobStore(inner, failKeys);
        var svc = Build(wrapper);

        // Replace each coord's BlobHandle.OpenAsync with one routed through the
        // flaky store — this is what license extraction will hit.
        var routedCoords = coords.Select(c =>
            (c.PackageName, c.Version, c.Bytes,
             Blob: c.Blob with
             {
                 OpenAsync = async ct => await wrapper.GetAsync(c.Blob.BlobKey, ct)
                     ?? throw new InvalidOperationException("vanished")
             })).ToList();

        // Track per-coord licence extractor calls so we can prove the failing two
        // never reach the extractor body.
        var calls = new System.Collections.Concurrent.ConcurrentBag<string>();
        LicenseExtractor.ExtractedMetadata Extract(string pkg, Stream s)
        {
            calls.Add(pkg);
            // Drain the stream so disposal semantics match production.
            using (s) { s.CopyTo(Stream.Null); }
            return new LicenseExtractor.ExtractedMetadata(new[] { "MIT" }, null);
        }

        var results = new ProxyFetchResult[total];
        await Parallel.ForEachAsync(routedCoords.Select((c, i) => (c, i)), async (item, ct) =>
        {
            var (coord, idx) = item;
            var req = new ProxyFetchRequest(
                OrgId: "o1", Ecosystem: "npm",
                PackageName: coord.PackageName, PurlName: coord.PackageName,
                Version: coord.Version, Purl: $"pkg:npm/{coord.PackageName}@{coord.Version}",
                File: $"{coord.PackageName}-{coord.Version}.tgz",
                Blob: coord.Blob,
                ExtractLicenses: s => Extract(coord.PackageName, s),
                UserId: null, ActorKind: null, SourceIp: null,
                MaxOsvScoreTolerance: 10.0,
                CacheAccess: null);
            results[idx] = await svc.RecordAndScanAsync(req, ct);
        });

        // All five first-fetch rows persisted, no exception bubbled.
        Assert.All(results, r => Assert.NotNull(r.VersionId));

        await using var conn = await _db.OpenAsync();
        var rowCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM package_versions");
        Assert.Equal(total, rowCount);

        // First three succeeded — licence rows should be present.
        for (var i = 0; i < failFrom; i++)
        {
            var versionId = results[i].VersionId!;
            var licCount = await conn.ExecuteScalarAsync<long>(
                "SELECT COUNT(*) FROM package_version_licenses WHERE package_version_id = @v",
                new { v = versionId });
            Assert.Equal(1, licCount);
        }

        // Last two failed on stream-open — extractor never ran, no licence rows.
        for (var i = failFrom; i < total; i++)
        {
            var versionId = results[i].VersionId!;
            var licCount = await conn.ExecuteScalarAsync<long>(
                "SELECT COUNT(*) FROM package_version_licenses WHERE package_version_id = @v",
                new { v = versionId });
            Assert.Equal(0, licCount);
        }

        // Extractor invoked only for the successful coordinates.
        Assert.Equal(failFrom, calls.Count);
    }

    /// <summary>
    /// Blob store that throws <see cref="IOException"/> on <see cref="GetAsync"/> for a
    /// configured set of keys. All other operations forward to the inner store, so we
    /// can <see cref="PutAsync"/> blobs first and only the licence-extraction read path
    /// faults. <see cref="ExistsAsync"/> stays truthful so ProxyFetchService doesn't
    /// re-cache.
    /// </summary>
    private sealed class FlakyBlobStore : IBlobStore
    {
        private readonly IBlobStore _inner;
        private readonly HashSet<string> _failGetKeys;

        public FlakyBlobStore(IBlobStore inner, HashSet<string> failGetKeys)
        {
            _inner = inner;
            _failGetKeys = failGetKeys;
        }

        public Task PutAsync(string key, Stream data, CancellationToken ct = default)
            => _inner.PutAsync(key, data, ct);

        public Task<Stream?> GetAsync(string key, CancellationToken ct = default)
        {
            if (_failGetKeys.Contains(key))
                throw new IOException($"simulated transient backend error for {key}");
            return _inner.GetAsync(key, ct);
        }

        public Task<bool> ExistsAsync(string key, CancellationToken ct = default)
            => _inner.ExistsAsync(key, ct);
        public Task DeleteAsync(string key, CancellationToken ct = default)
            => _inner.DeleteAsync(key, ct);
        public Task<long> GetTotalSizeAsync(CancellationToken ct = default)
            => _inner.GetTotalSizeAsync(ct);
        public IAsyncEnumerable<BlobInfo> ListAsync(string prefix, CancellationToken ct = default)
            => _inner.ListAsync(prefix, ct);
    }
}
