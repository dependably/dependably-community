using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Publish;
using Dependably.Infrastructure.Redis;
using Dependably.Infrastructure.Webhooks;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;

namespace Dependably.Tests.Unit;

/// <summary>
/// Tests for the tenant storage-quota gate on <see cref="PackagePublishService.StoreAndRecordAsync"/>.
///
/// The gate derives usage from the live <c>org_storage_bytes</c> view and charges
/// admitted-but-uncommitted bytes to a per-process ledger, so these assert on the two properties
/// that model has to hold:
/// - It still refuses concurrent publishes that individually fit but together overshoot (the
///   ledger, not a counter UPDATE, is what makes exactly one of them lose).
/// - Bytes that leave any plane — a version deleted, a cache artifact evicted — free real
///   headroom, because the sum is recomputed rather than decremented. A counter that missed one
///   of those decrements refused a tenant that was under its real quota, unrecoverably.
/// </summary>
[Trait("Category", "Unit")]
public sealed class QuotaReservationTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly InMemoryBlobStore _blobs = new();

    // One repository instance across every service this fixture builds: the in-flight
    // reservation ledger lives on it, so sharing it is what makes a publish and a concurrently
    // held proxy-fill reservation weigh the same ceiling.
    private readonly OrgRepository _orgs;

    public QuotaReservationTests() => _orgs = new OrgRepository(_db);

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme')");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private PackagePublishService Build()
    {
        var packages = new PackageRepository(_db);
        var audit = new AuditRepository(_db);
        var cfg = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["CLAIM_ENFORCEMENT"] = "off" })
            .Build();
        var resolver = new ClaimResolver(new ClaimRepository(_db), new AirGapMode(cfg));
        var gate = new PublishGate(cfg, resolver);
        var emitter = new Dependably.Infrastructure.Audit.AuditEmitter(
            new Dependably.Infrastructure.Audit.AuditEventRepository(_db),
            new Microsoft.AspNetCore.Http.HttpContextAccessor(),
            NullLogger<Dependably.Infrastructure.Audit.AuditEmitter>.Instance, cfg,
            new ServiceCollection().BuildServiceProvider(), new OrgRepository(_db), TimeProvider.System);
        var tiered = new TieredBlobStorage(_blobs, _blobs);
        var storage = new GlobalTenantStorageResolver(_db, tiered);
        var osv = new NullOsvSource();
        var scanner = new VulnerabilityScanService(new VulnerabilityScanService.Dependencies(
            _db, osv,
            new VulnerabilityRepository(_db, TimeProvider.System), audit, cfg,
            new NoAirGap(),
            NullLogger<VulnerabilityScanService>.Instance,
            TimeProvider.System,
            new OrgRepository(_db),
            Substitute.For<IPackageEventSink>(), new InProcessDistributedLock(TimeProvider.System),
            Dependably.Tests.Infrastructure.TestAlerts.NoOp(_db, TimeProvider.System)));
        var auditor = new Dependably.Infrastructure.Publish.PublishAuditor(audit, emitter);
        var licenses = new LicenseRepository(_db, TimeProvider.System, TestNormalizers.License(_db));
        return new PackagePublishService(packages, new PackageVersionFilesRepository(_db), _orgs, storage, gate,
            new Dependably.Security.NameBindingGate(cfg, new Dependably.Infrastructure.NameBindingRepository(_db), NullLogger<Dependably.Security.NameBindingGate>.Instance),
            new Dependably.Infrastructure.VersionTombstoneRepository(_db),
            new Dependably.Infrastructure.Edge.EdgePublishGuard(TestEdgeMode.Disabled()),
            auditor, scanner, licenses, NullLogger<PackagePublishService>.Instance);
    }

    private static PublishRequest Sample(string name, string version = "1.0.0", long size = 100) => new()
    {
        OrgId = "o1",
        Ecosystem = "npm",
        Name = name,
        PurlName = name,
        Version = version,
        Filename = $"{name}-{version}.tgz",
        Purl = $"pkg:npm/{name}@{version}",
        ArtifactBytes = new byte[size],
        Origin = "uploaded",
        SizeCap = long.MaxValue,
        ActorUserId = "u1",
    };

    // ── Concurrent publish: exactly one passes, one gets 413 ─────────────────

    [Fact]
    public async Task ConcurrentPublishes_OnlyOnePassesWhenBothTogetherExceedCap()
    {
        // Set quota to 1000 bytes. Two concurrent 600-byte publishes each fit individually
        // but together overshoot. The atomic reserve-before-write must ensure exactly one
        // succeeds and the other gets tenant_quota_exceeded.
        await _orgs.SetStorageQuotaBytesAsync("o1", 1_000);
        var svc = Build();

        var task1 = svc.StoreAndRecordAsync(Sample(name: "pkg-a", size: 600));
        var task2 = svc.StoreAndRecordAsync(Sample(name: "pkg-b", size: 600));
        var results = await Task.WhenAll(task1, task2);

        int acceptedCount = results.Count(r => r is PublishResult.Accepted);
        int rejectedCount = results.Count(r => r is PublishResult.Rejected { Code: "tenant_quota_exceeded" });

        Assert.Equal(1, acceptedCount);
        Assert.Equal(1, rejectedCount);

        // The rejected publish must not have written a blob.
        var rejected = results.OfType<PublishResult.Rejected>().Single();
        Assert.Equal(413, rejected.HttpStatus);
    }

    // ── Reservation released on blob/metadata failure ────────────────────────

    [Fact]
    public async Task PublishFailureAfterReservation_ReleasesTheHeadroomItClaimed()
    {
        // Quota 2000, one successful 600-byte publish, then a 400-byte publish that dies during
        // blob put. The failed publish must give its 400 bytes of headroom back: a follow-up
        // 1400-byte publish exactly fills the remaining ceiling (600 + 1400 = 2000) and must be
        // accepted. A leaked reservation would make that read as 600 + 400 + 1400 and 413.
        await _orgs.SetStorageQuotaBytesAsync("o1", 2_000);
        var svc = Build();

        Assert.IsType<PublishResult.Accepted>(await svc.StoreAndRecordAsync(Sample(name: "pkg-a", size: 600)));
        Assert.Equal(600, await ReadLiveStorageBytes());

        // Wire a blob store that throws on PutAsync to simulate a mid-publish failure.
        var throwingBlobs = new ThrowOnPutBlobStore(_blobs);
        var svcFailing = BuildWithRegistry(throwingBlobs);

        await Assert.ThrowsAnyAsync<Exception>(() =>
            svcFailing.StoreAndRecordAsync(Sample(name: "pkg-b", size: 400)));

        // Nothing committed, so the derived sum never saw the failed publish's bytes...
        Assert.Equal(600, await ReadLiveStorageBytes());
        // ...and the headroom it reserved is genuinely back.
        Assert.IsType<PublishResult.Accepted>(await svc.StoreAndRecordAsync(Sample(name: "pkg-c", size: 1_400)));
    }

    // ── Freed bytes free real headroom ───────────────────────────────────────

    [Fact]
    public async Task DeleteVersion_FreesTheQuotaHeadroomTheVersionHeld()
    {
        // Publish 600 against a 1000 cap, delete it, then publish the full 1000. The delete has
        // to free headroom, not just remove a row.
        await _orgs.SetStorageQuotaBytesAsync("o1", 1_000);
        var svc = Build();

        var accepted = Assert.IsType<PublishResult.Accepted>(
            await svc.StoreAndRecordAsync(Sample(name: "pkg-a", size: 600)));
        Assert.Equal(600, await ReadLiveStorageBytes());

        var packages = new PackageRepository(_db);
        await packages.DeleteVersionAsync(accepted.VersionId);

        Assert.Equal(0, await ReadLiveStorageBytes());
        Assert.IsType<PublishResult.Accepted>(await svc.StoreAndRecordAsync(Sample(name: "pkg-b", size: 1_000)));
    }

    [Fact]
    public async Task EvictedCacheBytes_DoNotKeepRefusingAPublishThatFitsTheRealUsage()
    {
        // The counter's unrecoverable failure mode, on the path that produced it: cache bytes are
        // counted into usage, then eviction deletes the cache_artifact row. A counter baselined
        // from those bytes never decrements — eviction had no counter to pay back — so the tenant
        // stays refused while sitting well under its real quota. Deriving the sum cannot do that.
        await _orgs.SetStorageQuotaBytesAsync("o1", 2_000);
        var svc = Build();

        // 800 bytes of proxied artefacts this tenant holds through the shared cache plane.
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO cache_artifact (id, ecosystem, name, version, filename, blob_key, content_hash, size_bytes) " +
                "VALUES ('ca1', 'npm', 'left-pad', '1.0.0', 'left-pad-1.0.0.tgz', 'proxy/aa', 'aa', 800)");
            await conn.ExecuteAsync(
                "INSERT INTO tenant_artifact_access (org_id, cache_artifact_id) VALUES ('o1', 'ca1')");
        }

        // A publish while those bytes are resident: 800 + 300 = 1100, inside the 2000 cap.
        Assert.IsType<PublishResult.Accepted>(await svc.StoreAndRecordAsync(Sample(name: "pkg-a", size: 300)));
        Assert.Equal(1_100, await ReadLiveStorageBytes());

        // Retention evicts the cache artifact. Real usage drops to the 300 hosted bytes.
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync("DELETE FROM tenant_artifact_access WHERE cache_artifact_id = 'ca1'");
            await conn.ExecuteAsync("DELETE FROM cache_artifact WHERE id = 'ca1'");
        }
        Assert.Equal(300, await ReadLiveStorageBytes());

        // 300 + 1000 = 1300, comfortably inside the cap. A counter stuck at 1100 would have made
        // this 2100 and returned 413.
        Assert.IsType<PublishResult.Accepted>(await svc.StoreAndRecordAsync(Sample(name: "pkg-b", size: 1_000)));
    }

    // ── One ceiling across write paths ───────────────────────────────────────

    [Fact]
    public async Task AProxyFillHoldingHeadroom_IsWeighedByAConcurrentPublish()
    {
        // Failure mode the split enabled: a proxy fill and a hosted publish each enforcing the
        // ceiling from its own reading admit a combined footprint approaching 2x the quota. Both
        // now reserve through the same gate, so bytes one has admitted but not yet committed are
        // visible to the other.
        await _orgs.SetStorageQuotaBytesAsync("o1", 1_000);
        var svc = Build();

        // A proxy fill of 600 bytes, admitted and mid-flight — nothing recorded on the cache
        // plane yet, so the live sum still reads 0.
        using var fill = await _orgs.TryReserveStorageAsync("o1", 600, quota: 1_000);
        Assert.NotNull(fill);
        Assert.Equal(0, await ReadLiveStorageBytes());

        // A 600-byte publish would make the combined footprint 1200 against a 1000 cap.
        var rejected = Assert.IsType<PublishResult.Rejected>(
            await svc.StoreAndRecordAsync(Sample(name: "pkg-a", size: 600)));
        Assert.Equal(413, rejected.HttpStatus);
        Assert.Equal("tenant_quota_exceeded", rejected.Code);

        // Once the fill completes and releases, the same publish fits.
        fill.Dispose();
        Assert.IsType<PublishResult.Accepted>(await svc.StoreAndRecordAsync(Sample(name: "pkg-a", size: 600)));
    }

    // ── Rows the gate never reserved still count ─────────────────────────────

    [Fact]
    public async Task PublishGate_CountsRowsItNeverReserved()
    {
        // Rows can exist that no reservation ever passed through — an import, a restore, a
        // publish from before the gate existed. Deriving from the view counts them for free.
        await _orgs.SetStorageQuotaBytesAsync("o1", 2_000);
        var svc = Build();

        await SeedHostedVersionAsync(sizeBytes: 800);

        var result = await svc.StoreAndRecordAsync(Sample(name: "new-pkg", size: 300));
        Assert.IsType<PublishResult.Accepted>(result);
        Assert.Equal(1_100, await ReadLiveStorageBytes());
    }

    [Fact]
    public async Task PublishGate_RejectsWhenRowsItNeverReservedAlreadyExceedTheCap()
    {
        // Same shape, over the cap: an org already at 800 of a 1000 ceiling cannot add 300.
        await _orgs.SetStorageQuotaBytesAsync("o1", 1_000);
        var svc = Build();

        await SeedHostedVersionAsync(sizeBytes: 800);

        var result = await svc.StoreAndRecordAsync(Sample(name: "new-pkg", size: 300));
        var rej = Assert.IsType<PublishResult.Rejected>(result);
        Assert.Equal(413, rej.HttpStatus);
        Assert.Equal("tenant_quota_exceeded", rej.Code);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private Task<long> ReadLiveStorageBytes() => _orgs.GetLiveStorageBytesAsync("o1");

    private async Task SeedHostedVersionAsync(long sizeBytes)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) " +
            "VALUES ('p1', 'o1', 'npm', 'legacy', 'legacy', 0)");
        await conn.ExecuteAsync(
            "INSERT INTO package_versions (id, package_id, version, purl, blob_key, size_bytes, origin) " +
            "VALUES ('v1', 'p1', '1.0.0', 'pkg:npm/legacy@1.0.0', 'k', @sizeBytes, 'uploaded')",
            new { sizeBytes });
    }

    private PackagePublishService BuildWithRegistry(IBlobStore registry)
    {
        var packages = new PackageRepository(_db);
        var audit = new AuditRepository(_db);
        var cfg = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["CLAIM_ENFORCEMENT"] = "off" })
            .Build();
        var resolver = new ClaimResolver(new ClaimRepository(_db), new AirGapMode(cfg));
        var gate = new PublishGate(cfg, resolver);
        var emitter = new Dependably.Infrastructure.Audit.AuditEmitter(
            new Dependably.Infrastructure.Audit.AuditEventRepository(_db),
            new Microsoft.AspNetCore.Http.HttpContextAccessor(),
            NullLogger<Dependably.Infrastructure.Audit.AuditEmitter>.Instance, cfg,
            new ServiceCollection().BuildServiceProvider(), new OrgRepository(_db), TimeProvider.System);
        var tiered = new TieredBlobStorage(_blobs, registry);
        var storage = new GlobalTenantStorageResolver(_db, tiered);
        var osv = new NullOsvSource();
        var scanner = new VulnerabilityScanService(new VulnerabilityScanService.Dependencies(
            _db, osv,
            new VulnerabilityRepository(_db, TimeProvider.System), audit, cfg,
            new NoAirGap(),
            NullLogger<VulnerabilityScanService>.Instance,
            TimeProvider.System,
            new OrgRepository(_db),
            Substitute.For<IPackageEventSink>(), new InProcessDistributedLock(TimeProvider.System),
            Dependably.Tests.Infrastructure.TestAlerts.NoOp(_db, TimeProvider.System)));
        var auditor = new Dependably.Infrastructure.Publish.PublishAuditor(audit, emitter);
        var licenses = new LicenseRepository(_db, TimeProvider.System, TestNormalizers.License(_db));
        return new PackagePublishService(packages, new PackageVersionFilesRepository(_db), _orgs, storage, gate,
            new Dependably.Security.NameBindingGate(cfg, new Dependably.Infrastructure.NameBindingRepository(_db), NullLogger<Dependably.Security.NameBindingGate>.Instance),
            new Dependably.Infrastructure.VersionTombstoneRepository(_db),
            new Dependably.Infrastructure.Edge.EdgePublishGuard(TestEdgeMode.Disabled()),
            auditor, scanner, licenses, NullLogger<PackagePublishService>.Instance);
    }

    /// <summary>Blob store that throws on PutAsync to simulate a blob-write failure.</summary>
    private sealed class ThrowOnPutBlobStore : IBlobStore
    {
        private readonly IBlobStore _inner;
        public ThrowOnPutBlobStore(IBlobStore inner) { _inner = inner; }
        public Task PutAsync(string key, Stream data, CancellationToken ct = default)
            => throw new InvalidOperationException("simulated blob write failure");
        public Task<Stream?> GetAsync(string key, CancellationToken ct = default) => _inner.GetAsync(key, ct);
        public Task<RangedStream?> GetRangeAsync(string key, long from, long to, CancellationToken ct = default) => _inner.GetRangeAsync(key, from, to, ct);
        public Task<bool> ExistsAsync(string key, CancellationToken ct = default) => _inner.ExistsAsync(key, ct);
        public Task DeleteAsync(string key, CancellationToken ct = default) => _inner.DeleteAsync(key, ct);
        public Task<long> GetTotalSizeAsync(CancellationToken ct = default) => _inner.GetTotalSizeAsync(ct);
        public IAsyncEnumerable<BlobInfo> ListAsync(string prefix, CancellationToken ct = default) => _inner.ListAsync(prefix, ct);
    }

    private sealed class NullOsvSource : IOsvSource
    {
        public Task<List<OsvAdvisory>> QueryAsync(string purl, CancellationToken ct = default)
            => Task.FromResult(new List<OsvAdvisory>());
        public Task<List<List<OsvAdvisory>>> QueryBatchAsync(IReadOnlyList<string> purls, CancellationToken ct = default)
            => Task.FromResult(purls.Select(_ => new List<OsvAdvisory>()).ToList());
    }

    private sealed class NoAirGap : IAirGapMode
    {
        public bool IsEnabled => false;
        public IReadOnlySet<string> DisabledJobs => new System.Collections.Generic.HashSet<string>();
        public bool IsJobDisabled(string jobName) => false;
    }
}
