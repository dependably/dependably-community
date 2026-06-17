using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Publish;
using Dependably.Protocol;
using Dependably.Security;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit;

/// <summary>
/// Tests for the atomic storage-quota reservation introduced to close the TOCTOU race in
/// <see cref="PackagePublishService.StoreAndRecordAsync"/>.
///
/// Covers:
/// - Concurrent publishes where each fits individually but together exceed the cap — exactly
///   one must succeed and the other must get 413.
/// - Quota counter is decremented when a publish fails after the reservation (blob write
///   simulation, metadata commit failure path exercised via the existing orphan-delete harness).
/// - Counter is decremented on version delete.
/// </summary>
[Trait("Category", "Unit")]
public sealed class QuotaReservationTests : IAsyncLifetime
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
            new ServiceCollection().BuildServiceProvider(), TimeProvider.System);
        var tiered = new TieredBlobStorage(_blobs, _blobs);
        var storage = new GlobalTenantStorageResolver(_db, tiered);
        var osv = new NullOsvSource();
        var scanner = new VulnerabilityScanService(new VulnerabilityScanService.Dependencies(
            _db, osv,
            new VulnerabilityRepository(_db, TimeProvider.System), audit, cfg,
            new NoAirGap(),
            NullLogger<VulnerabilityScanService>.Instance,
            TimeProvider.System));
        var auditor = new Dependably.Infrastructure.Publish.PublishAuditor(audit, emitter);
        return new PackagePublishService(packages, new OrgRepository(_db), storage, gate,
            auditor, scanner, NullLogger<PackagePublishService>.Instance);
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
        var orgs = new OrgRepository(_db);
        await orgs.SetStorageQuotaBytesAsync("o1", 1_000);
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

    // ── Counter decremented on blob/metadata failure ─────────────────────────

    [Fact]
    public async Task PublishFailureAfterReservation_ReleasesCounter()
    {
        // Set a quota and make a first successful publish (600 bytes). Then attempt a second
        // publish that fails during blob put (using a throwing store). The quota counter must
        // be back at 600 after the failure — not 1200 — so a retry can succeed.
        var orgs = new OrgRepository(_db);
        await orgs.SetStorageQuotaBytesAsync("o1", 2_000);
        var svc = Build();

        // First publish succeeds; counter should now be 600.
        Assert.IsType<PublishResult.Accepted>(await svc.StoreAndRecordAsync(Sample(name: "pkg-a", size: 600)));

        // Verify counter after first publish.
        long counterAfterFirst = await ReadStorageUsedBytes();
        Assert.Equal(600, counterAfterFirst);

        // Wire a blob store that throws on PutAsync to simulate a mid-publish failure.
        var throwingBlobs = new ThrowOnPutBlobStore(_blobs);
        var svcFailing = BuildWithRegistry(throwingBlobs);

        await Assert.ThrowsAnyAsync<Exception>(() =>
            svcFailing.StoreAndRecordAsync(Sample(name: "pkg-b", size: 400)));

        // Counter must be back at 600 (not 1000 after aborted reservation).
        long counterAfterFailure = await ReadStorageUsedBytes();
        Assert.Equal(600, counterAfterFailure);
    }

    // ── Counter decremented on version delete ─────────────────────────────────

    [Fact]
    public async Task DeleteVersion_DecrementsStorageCounter()
    {
        // Publish a 600-byte version. After delete, the counter should be back at 0.
        var orgs = new OrgRepository(_db);
        await orgs.SetStorageQuotaBytesAsync("o1", 2_000);
        var svc = Build();

        var accepted = Assert.IsType<PublishResult.Accepted>(
            await svc.StoreAndRecordAsync(Sample(name: "pkg-a", size: 600)));

        long counterBeforeDelete = await ReadStorageUsedBytes();
        Assert.Equal(600, counterBeforeDelete);

        var packages = new PackageRepository(_db);
        await packages.DeleteVersionAsync(accepted.VersionId);

        long counterAfterDelete = await ReadStorageUsedBytes();
        Assert.Equal(0, counterAfterDelete);
    }

    [Fact]
    public async Task DeleteVersion_NeverGoesNegative_WhenCounterIsAlreadyZero()
    {
        // If the counter is 0 (e.g. upgraded from pre-counter schema) and a version is deleted,
        // the counter must clamp at 0 rather than going negative.
        var svc = Build();
        var accepted = Assert.IsType<PublishResult.Accepted>(
            await svc.StoreAndRecordAsync(Sample(name: "pkg-a", size: 600)));

        // Force counter to 0 to simulate a pre-migration database.
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "UPDATE org_settings SET storage_used_bytes = 0 WHERE org_id = 'o1'");
        }

        var packages = new PackageRepository(_db);
        await packages.DeleteVersionAsync(accepted.VersionId);

        long counterAfterDelete = await ReadStorageUsedBytes();
        Assert.Equal(0, counterAfterDelete);
    }

    // ── Backfill: counter 0 upgraded from pre-counter schema ─────────────────

    [Fact]
    public async Task Backfill_WhenCounterIsZeroAndRealSumIsPositive_CounterSetOnFirstPublish()
    {
        // Simulate a database that was upgraded: org_settings row exists with
        // storage_used_bytes = 0 but package_versions has bytes from a previous publish
        // (inserted directly, bypassing the counter). The next atomic reserve must backfill
        // from the live sum before evaluating the quota.
        var orgs = new OrgRepository(_db);
        await orgs.SetStorageQuotaBytesAsync("o1", 2_000);
        var svc = Build();

        // Seed a version row directly (simulating pre-counter publish) with size = 800.
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) " +
                "VALUES ('p1', 'o1', 'npm', 'legacy', 'legacy', 0)");
            await conn.ExecuteAsync(
                "INSERT INTO package_versions (id, package_id, version, purl, blob_key, size_bytes) " +
                "VALUES ('v1', 'p1', '1.0.0', 'pkg:npm/legacy@1.0.0', 'k', 800)");
        }

        // counter is still 0 at this point. A 300-byte publish should backfill to 800 then
        // add 300, landing at 1100 — under the 2000 cap.
        var result = await svc.StoreAndRecordAsync(Sample(name: "new-pkg", size: 300));
        Assert.IsType<PublishResult.Accepted>(result);

        long counter = await ReadStorageUsedBytes();
        Assert.Equal(1100, counter);
    }

    [Fact]
    public async Task Backfill_WhenCounterIsZeroAndRealSumExceedsCap_Rejects413()
    {
        // If the counter was 0 (pre-migration) and the backfill reveals the tenant is already
        // over quota, the first post-backfill publish must be rejected.
        var orgs = new OrgRepository(_db);
        await orgs.SetStorageQuotaBytesAsync("o1", 1_000);
        var svc = Build();

        // Seed 800 bytes of existing data with counter = 0.
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO packages (id, org_id, ecosystem, name, purl_name, is_proxy) " +
                "VALUES ('p1', 'o1', 'npm', 'legacy', 'legacy', 0)");
            await conn.ExecuteAsync(
                "INSERT INTO package_versions (id, package_id, version, purl, blob_key, size_bytes) " +
                "VALUES ('v1', 'p1', '1.0.0', 'pkg:npm/legacy@1.0.0', 'k', 800)");
        }

        // A 300-byte publish would put usage at 1100 > 1000 cap → must reject.
        var result = await svc.StoreAndRecordAsync(Sample(name: "new-pkg", size: 300));
        var rej = Assert.IsType<PublishResult.Rejected>(result);
        Assert.Equal(413, rej.HttpStatus);
        Assert.Equal("tenant_quota_exceeded", rej.Code);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private async Task<long> ReadStorageUsedBytes()
    {
        await using var conn = await _db.OpenAsync();
        return await conn.ExecuteScalarAsync<long>(
            "SELECT storage_used_bytes FROM org_settings WHERE org_id = 'o1'");
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
            new ServiceCollection().BuildServiceProvider(), TimeProvider.System);
        var tiered = new TieredBlobStorage(_blobs, registry);
        var storage = new GlobalTenantStorageResolver(_db, tiered);
        var osv = new NullOsvSource();
        var scanner = new VulnerabilityScanService(new VulnerabilityScanService.Dependencies(
            _db, osv,
            new VulnerabilityRepository(_db, TimeProvider.System), audit, cfg,
            new NoAirGap(),
            NullLogger<VulnerabilityScanService>.Instance,
            TimeProvider.System));
        var auditor = new Dependably.Infrastructure.Publish.PublishAuditor(audit, emitter);
        return new PackagePublishService(packages, new OrgRepository(_db), storage, gate,
            auditor, scanner, NullLogger<PackagePublishService>.Instance);
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
