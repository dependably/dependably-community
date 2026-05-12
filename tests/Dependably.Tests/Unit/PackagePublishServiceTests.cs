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
using Xunit;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public sealed class PackagePublishServiceTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly InMemoryBlobStore _blobs = new();
    private RecordingOsvSource _osv = null!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme')");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private PackagePublishService Build(string claimEnforcement = "off")
    {
        var packages = new PackageRepository(_db);
        var audit = new AuditRepository(_db);
        var cfg = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["CLAIM_ENFORCEMENT"] = claimEnforcement })
            .Build();
        var resolver = new ClaimResolver(new ClaimRepository(_db), new AirGapMode(cfg));
        var gate = new PublishGate(cfg, resolver);
        // Wire the real emitter so audit_event dual-writes are exercised; assertions on the
        // typed table live in the integration tests where HttpContext is available.
        var emitter = new Dependably.Infrastructure.Audit.AuditEmitter(
            new Dependably.Infrastructure.Audit.AuditEventRepository(_db),
            new Microsoft.AspNetCore.Http.HttpContextAccessor(),
            NullLogger<Dependably.Infrastructure.Audit.AuditEmitter>.Instance, cfg,
            // SIEM queue is opt-in (#40); empty service provider yields a null forwarder
            // and the emit path becomes a no-op for SIEM, which is correct for unit tests.
            new Microsoft.Extensions.DependencyInjection.ServiceCollection().BuildServiceProvider());
        // Tier-shared bootstrap: PackagePublishService writes to Registry; in unit tests
        // both tiers point to the same in-memory store.
        var tiered = new TieredBlobStorage(_blobs, _blobs);
        // Post-publish vuln scan runs synchronously; route it at a recording test double so
        // we can assert it fired (and so individual tests can swap it for a throwing variant).
        _osv = new RecordingOsvSource();
        var scanner = new VulnerabilityScanService(_db, _osv,
            new VulnerabilityRepository(_db), audit, cfg,
            NullLogger<VulnerabilityScanService>.Instance);
        return new PackagePublishService(packages, tiered, audit, gate, emitter, scanner,
            NullLogger<PackagePublishService>.Instance);
    }

    private static PublishRequest Sample(string name = "lodash", string version = "1.0.0", long size = 100, string? origin = "uploaded") => new()
    {
        OrgId = "o1",
        Ecosystem = "npm",
        Name = name,
        PurlName = name,
        Version = version,
        Filename = $"{name.Replace('/', '-')}-{version}.tgz",
        Purl = $"pkg:npm/{name}@{version}",
        ArtifactBytes = new byte[size],
        Origin = origin!,
        SizeCap = long.MaxValue,
        ActorUserId = "u1",
    };

    [Fact]
    public async Task HappyPath_AcceptedReturnsCoordinatesAndStoresBlob()
    {
        var svc = Build();
        var result = await svc.StoreAndRecordAsync(Sample());
        var accepted = Assert.IsType<PublishResult.Accepted>(result);
        Assert.Equal("pkg:npm/lodash@1.0.0", accepted.Purl);
        Assert.False(string.IsNullOrEmpty(accepted.VersionId));
        Assert.False(string.IsNullOrEmpty(accepted.Sha256));

        // Blob actually written.
        Assert.True(await _blobs.ExistsAsync(BlobKeys.Hosted("o1", "npm", "lodash", "1.0.0", "lodash-1.0.0.tgz")));
    }

    [Fact]
    public async Task DuplicateVersion_RejectedWith409()
    {
        var svc = Build();
        await svc.StoreAndRecordAsync(Sample(version: "2.0.0"));
        var second = await svc.StoreAndRecordAsync(Sample(version: "2.0.0"));
        var rej = Assert.IsType<PublishResult.Rejected>(second);
        Assert.Equal(409, rej.HttpStatus);
        Assert.Equal("version_exists", rej.Code);
    }

    [Fact]
    public async Task SizeOverCap_RejectedWith413()
    {
        var svc = Build();
        var req = Sample(size: 200) with { SizeCap = 100 };
        var rej = Assert.IsType<PublishResult.Rejected>(await svc.StoreAndRecordAsync(req));
        Assert.Equal(413, rej.HttpStatus);
        Assert.Equal("size_limit_exceeded", rej.Code);
    }

    [Fact]
    public async Task PathTraversalInName_RejectedWith422()
    {
        var svc = Build();
        var rej = Assert.IsType<PublishResult.Rejected>(
            await svc.StoreAndRecordAsync(Sample(name: "../../etc/passwd")));
        Assert.Equal(422, rej.HttpStatus);
        Assert.Equal("path_unsafe", rej.Code);
    }

    [Fact]
    public async Task NpmScopedName_NotRejected_AllowsSlashInName()
    {
        // npm scoped names ("@scope/name") legitimately contain a slash. The service must
        // not reject them or every scoped publish would 422.
        var svc = Build();
        var result = await svc.StoreAndRecordAsync(Sample(name: "@scope/name"));
        Assert.IsType<PublishResult.Accepted>(result);
    }

    [Fact]
    public async Task FilenameWithSlash_RejectedWith422()
    {
        // The filename always lands in a path position, so slashes must reject regardless
        // of ecosystem. This is what blocks "../../filename" attacks via the filename.
        var svc = Build();
        var req = Sample() with { Filename = "evil/../../oops.tgz" };
        var rej = Assert.IsType<PublishResult.Rejected>(await svc.StoreAndRecordAsync(req));
        Assert.Equal(422, rej.HttpStatus);
    }

    [Fact]
    public async Task ClaimEnforcementOn_UnclaimedName_RejectedWith409()
    {
        var svc = Build(claimEnforcement: "on");
        var rej = Assert.IsType<PublishResult.Rejected>(await svc.StoreAndRecordAsync(Sample(name: "unclaimed-pkg")));
        Assert.Equal(409, rej.HttpStatus);
        Assert.Equal("claim_required", rej.Code);
    }

    [Fact]
    public async Task ClaimEnforcementOn_LocalOnlyClaim_Allowed()
    {
        // Seed a claim so the gate passes.
        await new ClaimRepository(_db).ApplyTransitionAsync(new ClaimTransition
        {
            ClaimId = Guid.NewGuid().ToString(),
            HistoryId = Guid.NewGuid().ToString(),
            OrgId = "o1",
            Ecosystem = "npm",
            Name = "internal-lib",
            PriorState = null,
            NewState = ClaimStateMachine.LocalOnly,
            Reason = "test",
            OccurredAt = DateTimeOffset.UtcNow,
        });
        var svc = Build(claimEnforcement: "on");
        var result = await svc.StoreAndRecordAsync(Sample(name: "internal-lib"));
        Assert.IsType<PublishResult.Accepted>(result);
    }

    [Fact]
    public async Task AllowOverwriteOff_DuplicateRejected()
    {
        var svc = Build();
        await svc.StoreAndRecordAsync(Sample(version: "1.0.0"));
        var dup = Sample(version: "1.0.0") with { AllowOverwrite = false };
        var rej = Assert.IsType<PublishResult.Rejected>(await svc.StoreAndRecordAsync(dup));
        Assert.Equal("version_exists", rej.Code);
    }

    [Fact]
    public async Task AllowOverwriteOn_DuplicateReplacesAndEmitsPackageReplaceEvent()
    {
        var svc = Build();
        var first = Sample(version: "1.0.0");
        var firstResult = (PublishResult.Accepted)await svc.StoreAndRecordAsync(first);
        var firstHash = firstResult.Sha256;

        // Different bytes → different hash → real overwrite.
        var second = first with { ArtifactBytes = new byte[]{ 1, 2, 3, 4, 5 }, AllowOverwrite = true };
        var secondResult = await svc.StoreAndRecordAsync(second);
        var accepted = Assert.IsType<PublishResult.Accepted>(secondResult);

        // VersionId is preserved across an overwrite (existing FKs don't get re-stitched).
        Assert.Equal(firstResult.VersionId, accepted.VersionId);
        Assert.NotEqual(firstHash, accepted.Sha256);

        await using var conn = await _db.OpenAsync();
        var replaceRows = (await conn.QueryAsync<(string Action, string Detail)>(
            "SELECT action, detail FROM audit_log WHERE org_id = 'o1' AND action = 'package.replace'"))
            .ToList();
        Assert.Single(replaceRows);
        Assert.Contains("sha256:" + firstHash, replaceRows[0].Detail);
        Assert.Contains("sha256:" + accepted.Sha256, replaceRows[0].Detail);
    }

    [Fact]
    public async Task AllowOverwriteOn_FreshName_BehavesAsNewPublish_NoReplaceEvent()
    {
        // AllowOverwrite=true on a name that doesn't exist yet must still create a new
        // version row (not error) and must NOT emit package.replace.
        var svc = Build();
        var req = Sample(name: "fresh-pkg", version: "1.0.0") with { AllowOverwrite = true };
        Assert.IsType<PublishResult.Accepted>(await svc.StoreAndRecordAsync(req));

        await using var conn = await _db.OpenAsync();
        var count = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE org_id = 'o1' AND action = 'package.replace' AND purl LIKE '%fresh-pkg%'");
        Assert.Equal(0, count);
    }

    [Fact]
    public async Task Import_RecordsActivityOnly_NotAuditLog()
    {
        // Imports are per-version operator events; they belong in `activity`, not in
        // `audit_log` (which is the tenant-level config/security sink). Mirrors the
        // version-delete fix in 5f6e1f0.
        var svc = Build();
        await svc.StoreAndRecordAsync(Sample(version: "10.0.0") with { AuditAction = "import", AuditDetail = "{\"batch_id\":\"b1\"}" });

        await using var conn = await _db.OpenAsync();
        var auditCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM audit_log WHERE org_id = 'o1' AND action = 'import' AND purl LIKE 'pkg:npm/lodash@10.%'");
        Assert.Equal(0, auditCount);

        var activity = (await conn.QueryAsync<(string EventType, string? Detail)>(
            "SELECT event_type, detail FROM activity WHERE org_id = 'o1' AND event_type = 'import' AND purl LIKE 'pkg:npm/lodash@10.%'"))
            .ToList();
        Assert.Single(activity);
        Assert.Equal("{\"batch_id\":\"b1\"}", activity[0].Detail);
    }

    [Fact]
    public async Task PostPublish_VulnScanFires_AndStampsVulnCheckedAt()
    {
        // Parity with proxy first-fetch: a hosted publish must synchronously scan so the
        // version no longer shows as "unscanned" the moment the publish returns. OSV returns
        // nothing here (custom name) — the row should still flip to a clean state.
        var svc = Build();
        var result = (PublishResult.Accepted)await svc.StoreAndRecordAsync(
            Sample(name: "internal-thing", version: "0.0.1"));

        Assert.Contains("pkg:npm/internal-thing@0.0.1", _osv.QueriedPurls);

        await using var conn = await _db.OpenAsync();
        var checkedAt = await conn.ExecuteScalarAsync<string?>(
            "SELECT vuln_checked_at FROM package_versions WHERE id = @id", new { id = result.VersionId });
        Assert.NotNull(checkedAt);
    }

    [Fact]
    public async Task PostPublish_OsvThrows_DoesNotFailPublish()
    {
        // OSV outage cannot fail an otherwise valid publish — the scheduled pass retries.
        var svc = Build();
        _osv.ThrowOnNextQuery = true;

        var result = await svc.StoreAndRecordAsync(Sample(name: "flaky", version: "0.0.1"));
        Assert.IsType<PublishResult.Accepted>(result);
    }

    // ── ValidateAsync ────────────────────────────────────────────────────────────

    [Fact]
    public async Task ValidateAsync_ValidRequest_ReturnsAcceptedWithEmptyVersionId()
    {
        // Dry-run on a brand-new package: all checks pass; no blob or version row is written.
        var svc = Build();
        var result = await svc.ValidateAsync(Sample());

        var accepted = Assert.IsType<PublishResult.Accepted>(result);
        Assert.Equal("", accepted.VersionId);
        Assert.False(string.IsNullOrEmpty(accepted.Sha256));
        Assert.Equal("pkg:npm/lodash@1.0.0", accepted.Purl);

        // No blob must have been stored.
        Assert.False(await _blobs.ExistsAsync(BlobKeys.Hosted("o1", "npm", "lodash", "1.0.0", "lodash-1.0.0.tgz")));

        // No version row must have been written.
        await using var conn = await _db.OpenAsync();
        var versionCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM package_versions WHERE purl = 'pkg:npm/lodash@1.0.0'");
        Assert.Equal(0, versionCount);
    }

    [Fact]
    public async Task ValidateAsync_PathUnsafeFilename_Rejects422()
    {
        var svc = Build();
        var req = Sample() with { Filename = "../evil.whl" };

        var result = await svc.ValidateAsync(req);

        var rej = Assert.IsType<PublishResult.Rejected>(result);
        Assert.Equal(422, rej.HttpStatus);
        Assert.Equal("path_unsafe", rej.Code);

        // No package version row should have been written.
        await using var conn = await _db.OpenAsync();
        var versionCount = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM package_versions");
        Assert.Equal(0, versionCount);
    }

    [Fact]
    public async Task ValidateAsync_ExistingVersionNoOverwrite_Rejects409()
    {
        // Seed a real version first.
        var svc = Build();
        await svc.StoreAndRecordAsync(Sample(version: "3.0.0"));

        // Dry-run with the same coordinates and AllowOverwrite=false must 409.
        var req = Sample(version: "3.0.0") with { AllowOverwrite = false };
        var result = await svc.ValidateAsync(req);

        var rej = Assert.IsType<PublishResult.Rejected>(result);
        Assert.Equal(409, rej.HttpStatus);
        Assert.Equal("version_exists", rej.Code);
    }

    /// <summary>
    /// Minimal IOsvSource: records every PURL queried, and answers each with an empty
    /// advisory list (the "OSV doesn't know this package" path). Tests opt into a throwing
    /// response by setting <see cref="ThrowOnNextQuery"/> — used to verify the publish path
    /// swallows OSV failures.
    /// </summary>
    private sealed class RecordingOsvSource : IOsvSource
    {
        public List<string> QueriedPurls { get; } = new();
        public bool ThrowOnNextQuery { get; set; }

        public Task<List<OsvAdvisory>> QueryAsync(string purl, CancellationToken ct = default)
        {
            QueriedPurls.Add(purl);
            if (ThrowOnNextQuery)
            {
                ThrowOnNextQuery = false;
                throw new HttpRequestException("simulated OSV outage");
            }
            return Task.FromResult(new List<OsvAdvisory>());
        }

        public Task<List<List<OsvAdvisory>>> QueryBatchAsync(IReadOnlyList<string> purls, CancellationToken ct = default)
        {
            QueriedPurls.AddRange(purls);
            return Task.FromResult(purls.Select(_ => new List<OsvAdvisory>()).ToList());
        }
    }
}
