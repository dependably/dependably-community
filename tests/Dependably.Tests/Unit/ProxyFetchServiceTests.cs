using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Redis;
using Dependably.Infrastructure.Webhooks;
using Dependably.Protocol;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;

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

    private ProxyFetchService Build(IBlobStore? blobOverride = null, IOsvSource? osvOverride = null, bool sourcePinningEnabled = false)
    {
        var blobs = blobOverride ?? _blobs;
        var packages = new PackageRepository(_db);
        var audit = new AuditRepository(_db);
        var licenses = new LicenseRepository(_db, TimeProvider.System, TestNormalizers.License(_db));
        var vulns = new VulnerabilityRepository(_db, TimeProvider.System);
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
        var airGap = Substitute.For<IAirGapMode>();
        airGap.IsEnabled.Returns(false);
        airGap.DisabledJobs.Returns(new System.Collections.Generic.HashSet<string>());
        airGap.IsJobDisabled(Arg.Any<string>()).Returns(false);
        var scanner = new VulnerabilityScanService(new VulnerabilityScanService.Dependencies(
            _db, osv, vulns, audit, cfg,
            airGap,
            NullLogger<VulnerabilityScanService>.Instance,
            TimeProvider.System,
            new OrgRepository(_db),
            Substitute.For<IPackageEventSink>(), new InProcessDistributedLock(TimeProvider.System),
            Dependably.Tests.Infrastructure.TestAlerts.NoOp(_db, TimeProvider.System)));
        var cacheArtifact = new CacheArtifactRepository(_db);
        var tenantAccess = new TenantArtifactAccessRepository(_db);
        var proxyVersions = new ProxyVersionRecorder(packages, audit, licenses, cacheArtifact,
            Substitute.For<IUpstreamLatestVersionResolver>(), NullLogger<ProxyVersionRecorder>.Instance);
        var blockGate = Dependably.Tests.Infrastructure.TestBlockGate.Create(_db, TimeProvider.System);
        var cacheRecorder = new CacheAccessRecorder(cacheArtifact, tenantAccess,
            NullLogger<CacheAccessRecorder>.Instance, TimeProvider.System);
        return new ProxyFetchService(cacheRecorder, proxyVersions, cacheArtifact, tenantAccess, scanner, blockGate, audit, TimeProvider.System,
            new Dependably.Infrastructure.SourcePinRepository(_db, new Microsoft.Extensions.Configuration.ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?> { ["PROXY_SOURCE_PINNING"] = sourcePinningEnabled ? "true" : "false" })
                .Build()));
    }

    private static async Task<BlobHandle> SeedBlobAsync(InMemoryBlobStore blobs, byte[] bytes)
    {
        string sha = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes)).ToLowerInvariant();
        string key = BlobKeys.Proxy(sha);
        await blobs.PutAsync(key, new MemoryStream(bytes));
        return new BlobHandle(key, sha, bytes.LongLength,
            async ct => await blobs.GetAsync(key, ct)
                ?? throw new InvalidOperationException($"blob {key} vanished"));
    }

    [Fact]
    public async Task RecordAndScanAsync_clean_version_returns_Allowed_and_caches_blob()
    {
        var svc = Build();

        byte[] bytes = "tarball-bytes"u8.ToArray();
        var blob = await SeedBlobAsync(_blobs, bytes);
        var result = await svc.RecordAndScanAsync(new ProxyFetchRequest(
            OrgId: "o1", Ecosystem: "npm",
            PackageName: "left-pad", PurlName: "left-pad",
            Version: "1.0.0", Purl: "pkg:npm/left-pad@1.0.0",
            File: "left-pad-1.0.0.tgz", Blob: blob,
            ExtractLicenses: null,
            UserId: null, ActorKind: null, SourceIp: "127.0.0.1",
            MaxOsvScoreTolerance: 10.0,
            CacheAccess: new CacheAccess("o1", "npm", "left-pad", "1.0.0", "left-pad-1.0.0.tgz",
                Sha256: "", SizeBytes: 0, BlobKey: "", UpstreamUrl: "https://upstream.test/artifact")));

        Assert.Equal(BlockDecision.Allowed, result.Decision);
        Assert.True(await _blobs.ExistsAsync(result.BlobKey));

        // Catalogued on the cache plane, and scanned there. Asserting vuln_checked_at is what stops
        // this passing on a fetch that skipped the scan entirely.
        await using var conn = await _db.OpenAsync();
        var (cacheArtifactId, vulnCheckedAt) = await conn.QuerySingleAsync<(string Id, string? VulnCheckedAt)>(
            "SELECT id AS Id, vuln_checked_at AS VulnCheckedAt FROM cache_artifact " +
            "WHERE ecosystem = 'npm' AND name = 'left-pad' AND version = '1.0.0'");
        Assert.NotNull(vulnCheckedAt);
        Assert.Equal(1, await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM tenant_artifact_access WHERE org_id = 'o1' AND cache_artifact_id = @id",
            new { id = cacheArtifactId }));

        // And nowhere else: package_versions is the hosted plane.
        Assert.Equal(0, await conn.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM package_versions"));
    }

    [Fact]
    public async Task RecordAndScanAsync_source_pin_blocks_second_upstream_for_same_name()
    {
        // A name first served by one upstream is pinned to that upstream. A later first-fetch of
        // the same name resolved from a DIFFERENT upstream (dependency-confusion fallback) is
        // refused before any version row is recorded.
        var svc = Build(sourcePinningEnabled: true);

        byte[] bytesA = "left-pad-from-private"u8.ToArray();
        var blobA = await SeedBlobAsync(_blobs, bytesA);
        var first = await svc.RecordAndScanAsync(new ProxyFetchRequest(
            OrgId: "o1", Ecosystem: "npm",
            PackageName: "left-pad", PurlName: "left-pad",
            Version: "1.0.0", Purl: "pkg:npm/left-pad@1.0.0",
            File: "left-pad-1.0.0.tgz", Blob: blobA,
            ExtractLicenses: null,
            UserId: null, ActorKind: null, SourceIp: "127.0.0.1",
            MaxOsvScoreTolerance: 10.0,
            CacheAccess: new CacheAccess("o1", "npm", "left-pad", "1.0.0", "left-pad-1.0.0.tgz",
                Sha256: "", SizeBytes: 0, BlobKey: "", UpstreamUrl: "https://upstream.test/artifact"),
            UpstreamUrl: "https://private.registry.example/left-pad/-/left-pad-1.0.0.tgz"));
        Assert.Equal(BlockDecision.Allowed, first.Decision);

        // Same name, different version, served from a different upstream host → blocked.
        byte[] bytesB = "left-pad-from-public"u8.ToArray();
        var blobB = await SeedBlobAsync(_blobs, bytesB);
        var second = await svc.RecordAndScanAsync(new ProxyFetchRequest(
            OrgId: "o1", Ecosystem: "npm",
            PackageName: "left-pad", PurlName: "left-pad",
            Version: "1.0.1", Purl: "pkg:npm/left-pad@1.0.1",
            File: "left-pad-1.0.1.tgz", Blob: blobB,
            ExtractLicenses: null,
            UserId: null, ActorKind: null, SourceIp: "127.0.0.1",
            MaxOsvScoreTolerance: 10.0,
            CacheAccess: new CacheAccess("o1", "npm", "left-pad", "1.0.1", "left-pad-1.0.1.tgz",
                Sha256: "", SizeBytes: 0, BlobKey: "", UpstreamUrl: "https://upstream.test/artifact"),
            UpstreamUrl: "https://registry.npmjs.org/left-pad/-/left-pad-1.0.1.tgz"));
        Assert.Equal(BlockDecision.Blocked, second.Decision);
        // The source-pin gate refuses before the artefact is catalogued, so the diverging version
        // was never adopted onto the cache plane.
        await using (var conn = await _db.OpenAsync())
        {
            Assert.Equal(0, await conn.ExecuteScalarAsync<long>(
                "SELECT COUNT(*) FROM cache_artifact WHERE ecosystem = 'npm' AND name = 'left-pad' AND version = '1.0.1'"));
        }

        // Same name from the ORIGINAL upstream still serves.
        byte[] bytesC = "left-pad-from-private-2"u8.ToArray();
        var blobC = await SeedBlobAsync(_blobs, bytesC);
        var third = await svc.RecordAndScanAsync(new ProxyFetchRequest(
            OrgId: "o1", Ecosystem: "npm",
            PackageName: "left-pad", PurlName: "left-pad",
            Version: "1.0.2", Purl: "pkg:npm/left-pad@1.0.2",
            File: "left-pad-1.0.2.tgz", Blob: blobC,
            ExtractLicenses: null,
            UserId: null, ActorKind: null, SourceIp: "127.0.0.1",
            MaxOsvScoreTolerance: 10.0,
            CacheAccess: new CacheAccess("o1", "npm", "left-pad", "1.0.2", "left-pad-1.0.2.tgz",
                Sha256: "", SizeBytes: 0, BlobKey: "", UpstreamUrl: "https://upstream.test/artifact"),
            UpstreamUrl: "https://private.registry.example/left-pad/-/left-pad-1.0.2.tgz"));
        Assert.Equal(BlockDecision.Allowed, third.Decision);
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

        byte[] bytes = "malicious-artifact"u8.ToArray();
        var blob = await SeedBlobAsync(_blobs, bytes);
        var result = await svc.RecordAndScanAsync(new ProxyFetchRequest(
            OrgId: "o1", Ecosystem: "maven",
            PackageName: "com.example:lib", PurlName: "com.example:lib",
            Version: "1.0.0", Purl: "pkg:maven/com.example/lib@1.0.0",
            File: "lib-1.0.0.jar", Blob: blob,
            ExtractLicenses: null,
            UserId: null, ActorKind: null, SourceIp: "127.0.0.1",
            MaxOsvScoreTolerance: 4.0,
            CacheAccess: new CacheAccess("o1", "maven", "com.example:lib", "1.0.0", "lib-1.0.0.jar",
                Sha256: "", SizeBytes: 0, BlobKey: "", UpstreamUrl: "https://upstream.test/artifact")));

        Assert.Equal(BlockDecision.Blocked, result.Decision);
    }

    [Theory]
    [InlineData("block_new")]
    [InlineData("block_all")]
    public async Task RecordAndScanAsync_deprecated_first_fetch_blocks_and_does_not_cache(string mode)
    {
        // Both blocking modes refuse a deprecated version on the first fetch (cache miss). The
        // gate runs before recording, so no version row is created — the controllers' cache-hit
        // lookup then keeps missing and every later request re-enters this path and re-blocks.
        var svc = Build();

        byte[] bytes = "deprecated-tarball"u8.ToArray();
        var blob = await SeedBlobAsync(_blobs, bytes);
        var result = await svc.RecordAndScanAsync(new ProxyFetchRequest(
            OrgId: "o1", Ecosystem: "npm",
            PackageName: "abandoned", PurlName: "abandoned",
            Version: "1.0.0", Purl: "pkg:npm/abandoned@1.0.0",
            File: "abandoned-1.0.0.tgz", Blob: blob,
            ExtractLicenses: null,
            UserId: null, ActorKind: null, SourceIp: "127.0.0.1",
            MaxOsvScoreTolerance: 10.0,
            CacheAccess: new CacheAccess("o1", "npm", "abandoned", "1.0.0", "abandoned-1.0.0.tgz",
                Sha256: "", SizeBytes: 0, BlobKey: "", UpstreamUrl: "https://upstream.test/artifact"),
            Deprecated: "use successor@2 instead",
            BlockDeprecatedMode: mode));

        Assert.Equal(BlockDecision.Blocked, result.Decision);

        await using var conn = await _db.OpenAsync();
        // Nothing catalogued on either plane: the gate runs before the artefact is adopted.
        Assert.Equal(0, await conn.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM package_versions"));
        Assert.Equal(0, await conn.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM cache_artifact"));
        long blockCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM activity WHERE event_type = 'blocked_deprecated'");
        Assert.Equal(1, blockCount);
    }

    [Fact]
    public async Task RecordAndScanAsync_deprecated_warn_mode_first_fetch_records_normally()
    {
        // warn never blocks: a deprecated version is still cached on first fetch (the UI/API
        // surface the deprecation status separately).
        var svc = Build();

        byte[] bytes = "warn-tarball"u8.ToArray();
        var blob = await SeedBlobAsync(_blobs, bytes);
        var result = await svc.RecordAndScanAsync(new ProxyFetchRequest(
            OrgId: "o1", Ecosystem: "npm",
            PackageName: "warned", PurlName: "warned",
            Version: "1.0.0", Purl: "pkg:npm/warned@1.0.0",
            File: "warned-1.0.0.tgz", Blob: blob,
            ExtractLicenses: null,
            UserId: null, ActorKind: null, SourceIp: "127.0.0.1",
            MaxOsvScoreTolerance: 10.0,
            CacheAccess: new CacheAccess("o1", "npm", "warned", "1.0.0", "warned-1.0.0.tgz",
                Sha256: "", SizeBytes: 0, BlobKey: "", UpstreamUrl: "https://upstream.test/artifact"),
            Deprecated: "deprecated upstream",
            BlockDeprecatedMode: "warn"));

        Assert.Equal(BlockDecision.Allowed, result.Decision);

        await using var conn = await _db.OpenAsync();
        Assert.Equal(1, await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM cache_artifact WHERE ecosystem = 'npm' AND name = 'warned' AND version = '1.0.0'"));
    }

    [Fact]
    public async Task RecordAndScanAsync_records_cache_access_when_provided()
    {
        var svc = Build();

        byte[] bytes = "tarball"u8.ToArray();
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
        long count = await conn.ExecuteScalarAsync<long>(
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
        for (int i = 0; i < total; i++)
        {
            byte[] bytes = System.Text.Encoding.UTF8.GetBytes($"tar-{i}");
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
                CacheAccess: new CacheAccess("o1", "npm", coord.PackageName, coord.Version,
                    $"{coord.PackageName}-{coord.Version}.tgz",
                    Sha256: "", SizeBytes: 0, BlobKey: "",
                    UpstreamUrl: $"https://registry.npmjs.org/{coord.PackageName}"));
            results[idx] = await svc.RecordAndScanAsync(req, ct);
        });

        // Every fetch was allowed and none threw: a failing extractor must not fail the fetch.
        Assert.All(results, r => Assert.Equal(BlockDecision.Allowed, r.Decision));

        await using var conn = await _db.OpenAsync();

        // All five catalogued on the cache plane, and none on the hosted plane.
        Assert.Equal(total, await conn.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM cache_artifact"));
        Assert.Equal(total, await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM tenant_artifact_access WHERE org_id = 'o1'"));
        Assert.Equal(0, await conn.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM package_versions"));

        // First three succeeded — licence rows present, owned by the cache artefact.
        for (int i = 0; i < failFrom; i++)
        {
            long licCount = await conn.ExecuteScalarAsync<long>(
                """
                SELECT COUNT(*) FROM package_version_licenses pvl
                JOIN cache_artifact ca ON ca.id = pvl.cache_artifact_id
                WHERE pvl.owner_kind = 'cache_artifact' AND ca.name = @name
                """,
                new { name = routedCoords[i].PackageName });
            Assert.Equal(1, licCount);
        }

        // Last two failed on stream-open — extractor never ran, no licence rows.
        for (int i = failFrom; i < total; i++)
        {
            long licCount = await conn.ExecuteScalarAsync<long>(
                """
                SELECT COUNT(*) FROM package_version_licenses pvl
                JOIN cache_artifact ca ON ca.id = pvl.cache_artifact_id
                WHERE pvl.owner_kind = 'cache_artifact' AND ca.name = @name
                """,
                new { name = routedCoords[i].PackageName });
            Assert.Equal(0, licCount);
        }

        // Extractor invoked only for the successful coordinates.
        Assert.Equal(failFrom, calls.Count);
    }

    // ── provenance fail-closed ingest ────────────────────────────────────────

    [Theory]
    [InlineData("failed")]
    [InlineData("unsigned")]
    public async Task RecordAndScanAsync_provenance_block_failed_does_not_cache(string status)
    {
        // Under verify=block a version that fails signature verification (or is unsigned) is
        // refused before recording, exactly like the deprecated first-fetch gate: no version row,
        // so subsequent requests re-enter this path and re-block. The staged blob is an orphan.
        var svc = Build();

        byte[] bytes = "unverified-tarball"u8.ToArray();
        var blob = await SeedBlobAsync(_blobs, bytes);
        var result = await svc.RecordAndScanAsync(new ProxyFetchRequest(
            OrgId: "o1", Ecosystem: "npm",
            PackageName: "spoofed", PurlName: "spoofed",
            Version: "1.0.0", Purl: "pkg:npm/spoofed@1.0.0",
            File: "spoofed-1.0.0.tgz", Blob: blob,
            ExtractLicenses: null,
            UserId: null, ActorKind: null, SourceIp: "127.0.0.1",
            MaxOsvScoreTolerance: 10.0,
            CacheAccess: new CacheAccess("o1", "npm", "spoofed", "1.0.0", "spoofed-1.0.0.tgz",
                Sha256: "", SizeBytes: 0, BlobKey: "", UpstreamUrl: "https://upstream.test/artifact"),
            ProvenanceStatus: status,
            VerifyProvenanceMode: "block"));

        Assert.Equal(BlockDecision.Blocked, result.Decision);

        await using var conn = await _db.OpenAsync();
        // Nothing catalogued on either plane: an unverified artefact is never adopted.
        Assert.Equal(0, await conn.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM package_versions"));
        Assert.Equal(0, await conn.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM cache_artifact"));
        long blockCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM activity WHERE event_type = 'blocked_provenance'");
        Assert.Equal(1, blockCount);
        // The tenant-level security event is recorded (and SIEM-forwarded via audit_log).
        long auditCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'provenance_verification_failed'");
        Assert.Equal(1, auditCount);
    }

    [Fact]
    public async Task RecordAndScanAsync_provenance_verified_records_and_persists_status()
    {
        var svc = Build();

        byte[] bytes = "signed-tarball"u8.ToArray();
        var blob = await SeedBlobAsync(_blobs, bytes);
        var result = await svc.RecordAndScanAsync(new ProxyFetchRequest(
            OrgId: "o1", Ecosystem: "npm",
            PackageName: "trusted", PurlName: "trusted",
            Version: "1.0.0", Purl: "pkg:npm/trusted@1.0.0",
            File: "trusted-1.0.0.tgz", Blob: blob,
            ExtractLicenses: null,
            UserId: null, ActorKind: null, SourceIp: "127.0.0.1",
            MaxOsvScoreTolerance: 10.0,
            CacheAccess: new CacheAccess("o1", "npm", "trusted", "1.0.0", "trusted-1.0.0.tgz",
                Sha256: "", SizeBytes: 0, BlobKey: "", UpstreamUrl: "https://upstream.test/artifact"),
            ProvenanceStatus: "verified",
            ProvenanceSigner: "SHA256:anchor",
            VerifyProvenanceMode: "block"));

        Assert.Equal(BlockDecision.Allowed, result.Decision);

        await using var conn = await _db.OpenAsync();
        var prov = await conn.QuerySingleAsync<ProvenanceRow>(
            "SELECT provenance_status AS Status, provenance_signer AS Signer FROM cache_artifact " +
            "WHERE ecosystem = 'npm' AND name = 'trusted' AND version = '1.0.0'");
        Assert.Equal("verified", prov.Status);
        Assert.Equal("SHA256:anchor", prov.Signer);
    }

    [Fact]
    public async Task RecordAndScanAsync_provenance_warn_mode_records_failed_status_without_blocking()
    {
        // warn never blocks: a version that failed verification is still cached, but the failure
        // is persisted so the UI/audit surface it.
        var svc = Build();

        byte[] bytes = "warn-prov-tarball"u8.ToArray();
        var blob = await SeedBlobAsync(_blobs, bytes);
        var result = await svc.RecordAndScanAsync(new ProxyFetchRequest(
            OrgId: "o1", Ecosystem: "npm",
            PackageName: "warned-prov", PurlName: "warned-prov",
            Version: "1.0.0", Purl: "pkg:npm/warned-prov@1.0.0",
            File: "warned-prov-1.0.0.tgz", Blob: blob,
            ExtractLicenses: null,
            UserId: null, ActorKind: null, SourceIp: "127.0.0.1",
            MaxOsvScoreTolerance: 10.0,
            CacheAccess: new CacheAccess("o1", "npm", "warned-prov", "1.0.0", "warned-prov-1.0.0.tgz",
                Sha256: "", SizeBytes: 0, BlobKey: "", UpstreamUrl: "https://upstream.test/artifact"),
            ProvenanceStatus: "failed",
            VerifyProvenanceMode: "warn"));

        Assert.Equal(BlockDecision.Allowed, result.Decision);

        await using var conn = await _db.OpenAsync();
        var prov = await conn.QuerySingleAsync<ProvenanceRow>(
            "SELECT provenance_status AS Status, provenance_signer AS Signer FROM cache_artifact " +
            "WHERE ecosystem = 'npm' AND name = 'warned-prov' AND version = '1.0.0'");
        Assert.Equal("failed", prov.Status);
    }

    /// <summary>
    /// Mixed partial-failure fan-out (house rule): a burst of first-fetches where some versions
    /// verify, some fail, and some are unsigned, all under verify=block in the same call set. The
    /// verified versions must record with status 'verified'; the failed/unsigned ones must be
    /// refused and never recorded — so the catalogue ends up holding exactly the verified subset.
    /// </summary>
    [Fact]
    public async Task RecordAndScanAsync_mixed_provenance_outcomes_blocks_only_unverified()
    {
        var svc = Build();

        var coords = new[]
        {
            (Name: "good-a", Status: "verified", Signer: (string?)"SHA256:anchor"),
            (Name: "bad-b", Status: "failed", Signer: (string?)null),
            (Name: "good-c", Status: "verified", Signer: (string?)"SHA256:anchor"),
            (Name: "old-d", Status: "unsigned", Signer: (string?)null),
        };

        var results = new System.Collections.Concurrent.ConcurrentDictionary<string, ProxyFetchResult>();
        await Parallel.ForEachAsync(coords, async (c, ct) =>
        {
            byte[] bytes = System.Text.Encoding.UTF8.GetBytes($"tar-{c.Name}");
            var blob = await SeedBlobAsync(_blobs, bytes);
            var result = await svc.RecordAndScanAsync(new ProxyFetchRequest(
                OrgId: "o1", Ecosystem: "npm",
                PackageName: c.Name, PurlName: c.Name,
                Version: "1.0.0", Purl: $"pkg:npm/{c.Name}@1.0.0",
                File: $"{c.Name}-1.0.0.tgz", Blob: blob,
                ExtractLicenses: null,
                UserId: null, ActorKind: null, SourceIp: "127.0.0.1",
                MaxOsvScoreTolerance: 10.0,
                CacheAccess: new CacheAccess("o1", "npm", c.Name, "1.0.0", $"{c.Name}-1.0.0.tgz",
                    Sha256: "", SizeBytes: 0, BlobKey: "",
                    UpstreamUrl: $"https://registry.npmjs.org/{c.Name}"),
                ProvenanceStatus: c.Status,
                ProvenanceSigner: c.Signer,
                VerifyProvenanceMode: "block"), ct);
            results[c.Name] = result;
        });

        // Verified versions allowed + recorded; failed/unsigned blocked + not recorded.
        Assert.Equal(BlockDecision.Allowed, results["good-a"].Decision);
        Assert.Equal(BlockDecision.Allowed, results["good-c"].Decision);
        Assert.Equal(BlockDecision.Blocked, results["bad-b"].Decision);
        Assert.Equal(BlockDecision.Blocked, results["old-d"].Decision);

        await using var conn = await _db.OpenAsync();
        // Exactly the two verified versions made it into the catalogue — and the blocked
        // coordinates are absent, not merely unflagged.
        Assert.Equal(0, await conn.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM package_versions"));
        var cached = (await conn.QueryAsync<string>(
            "SELECT name FROM cache_artifact WHERE provenance_status = 'verified' ORDER BY name")).ToList();
        Assert.Equal(new[] { "good-a", "good-c" }, cached);
        Assert.Equal(2, await conn.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM cache_artifact"));
        // Two block events (one per refused version).
        long blockCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM activity WHERE event_type = 'blocked_provenance'");
        Assert.Equal(2, blockCount);
    }

    /// <summary>
    /// The cache_artifact.name written by the shared proxy choke point must equal
    /// request.PurlName (the canonical, normalized form), not whatever raw name the caller
    /// placed in CacheAccess.Name. The cross-plane version-count and vuln-count joins use
    /// ca.name = p.purl_name; a divergent case breaks them silently.
    ///
    /// Regression test for the shared-path structural guard in
    /// ProxyFetchService.RecordCacheAccessAsync: even when CacheAccess.Name carries a
    /// mixed-case raw name (simulating the pre-fix RPM path), the persisted row must carry
    /// the PurlName value.
    /// </summary>
    [Fact]
    public async Task RecordAndScanAsync_cache_artifact_name_uses_purlname_not_raw_cache_access_name()
    {
        // CacheAccess.Name is the mixed-case raw name; PurlName is the canonical form.
        // Before the structural guard, the raw name was persisted verbatim, breaking the
        // ca.name = p.purl_name join for packages whose names are not fully lowercased.
        const string rawName = "perl-AutoLoader";
        const string purlName = "perl-autoloader";

        var svc = Build();

        byte[] bytes = "rpm-tarball"u8.ToArray();
        var blob = await SeedBlobAsync(_blobs, bytes);
        await svc.RecordAndScanAsync(new ProxyFetchRequest(
            OrgId: "o1", Ecosystem: "rpm",
            PackageName: rawName, PurlName: purlName,
            Version: "5.74-502.fc41", Purl: $"pkg:rpm/fedora/perl-autoloader@5.74-502.fc41",
            File: "perl-AutoLoader-5.74-502.fc41.noarch.rpm", Blob: blob,
            ExtractLicenses: null,
            UserId: null, ActorKind: null, SourceIp: null,
            MaxOsvScoreTolerance: 10.0,
            CacheAccess: new CacheAccess(
                OrgId: "o1", Ecosystem: "rpm",
                Name: rawName,  // raw mixed-case, as the pre-fix RPM path passed it
                Version: "5.74-502.fc41",
                Filename: "perl-AutoLoader-5.74-502.fc41.noarch.rpm",
                Sha256: "", SizeBytes: 0, BlobKey: "",
                UpstreamUrl: "https://dl.fedoraproject.org/perl-AutoLoader-5.74-502.fc41.noarch.rpm")));

        await using var conn = await _db.OpenAsync();

        // The persisted name must be the canonical PurlName, not the raw CacheAccess.Name.
        // If the structural guard is absent (Change 1 reverted), this returns rawName and the
        // assertion fails.
        string? persistedName = await conn.ExecuteScalarAsync<string?>(
            "SELECT name FROM cache_artifact WHERE ecosystem = 'rpm'");
        Assert.Equal(purlName, persistedName);

        // Confirm exactly one row was written.
        long count = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM cache_artifact WHERE ecosystem = 'rpm'");
        Assert.Equal(1, count);
    }

    /// <summary>
    /// Blob store that throws <see cref="IOException"/> on <see cref="GetAsync"/> for a
    /// configured set of keys. All other operations forward to the inner store, so we
    /// can <see cref="PutAsync"/> blobs first and only the licence-extraction read path
    /// faults. <see cref="ExistsAsync"/> stays truthful so ProxyFetchService doesn't
    /// re-cache.
    /// </summary>
    /// <summary>
    /// The cache plane is where a proxied artefact is gated: the OSV scan, the malicious/KEV/EPSS
    /// gates, the licence gates and the release-age hold all key off its <c>cache_artifact</c> row.
    /// If the recorder cannot produce that row — after its retry — there is nothing to gate against,
    /// so the fetch is refused rather than served ungated. Nothing is written on either plane and no
    /// decision is returned at all: the caller sees the exception and maps it to 503.
    /// </summary>
    [Fact]
    public async Task RecordAndScanAsync_throws_when_cache_plane_unavailable_and_serves_nothing()
    {
        var svc = Build();

        // Take the cache plane away. Both recorder attempts now fail, so no catalogue row exists.
        await using (var setup = await _db.OpenAsync())
        {
            await TestSchemaViews.DropAsync(setup);
            await setup.ExecuteAsync("DROP TABLE tenant_artifact_access");
            await setup.ExecuteAsync("DROP TABLE cache_artifact");
        }

        byte[] bytes = "ungatable-tarball"u8.ToArray();
        var blob = await SeedBlobAsync(_blobs, bytes);

        await Assert.ThrowsAsync<ProxyCatalogueUnavailableException>(() =>
            svc.RecordAndScanAsync(new ProxyFetchRequest(
                OrgId: "o1", Ecosystem: "npm",
                PackageName: "ungatable", PurlName: "ungatable",
                Version: "1.0.0", Purl: "pkg:npm/ungatable@1.0.0",
                File: "ungatable-1.0.0.tgz", Blob: blob,
                ExtractLicenses: null,
                UserId: null, ActorKind: null, SourceIp: "127.0.0.1",
                MaxOsvScoreTolerance: 10.0,
                CacheAccess: new CacheAccess("o1", "npm", "ungatable", "1.0.0", "ungatable-1.0.0.tgz",
                    Sha256: "", SizeBytes: 0, BlobKey: "", UpstreamUrl: "https://upstream.test/artifact"))));

        // The refused fetch left no trace on the hosted plane either — no zombie stand-in row.
        await using var conn = await _db.OpenAsync();
        Assert.Equal(0, await conn.ExecuteScalarAsync<long>("SELECT COUNT(*) FROM package_versions"));
    }

    /// <summary>
    /// A class with settable properties, not a positional record: in a compound query Dapper
    /// validates ctor parameter types against the provider's reported column types, and a nullable
    /// TEXT column with no declared type comes back as byte[].
    /// </summary>
    private sealed class ProvenanceRow
    {
        public string? Status { get; set; }
        public string? Signer { get; set; }
    }

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
            return _failGetKeys.Contains(key) ? throw new IOException($"simulated transient backend error for {key}") : _inner.GetAsync(key, ct);
        }

        public Task<RangedStream?> GetRangeAsync(string key, long from, long to, CancellationToken ct = default)
            => _inner.GetRangeAsync(key, from, to, ct);
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
