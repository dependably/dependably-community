using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Publish;
using Dependably.Infrastructure.Redis;
using Dependably.Infrastructure.Webhooks;
using Dependably.Security;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;

namespace Dependably.Tests.Unit;

/// <summary>
/// Version-granular delete tombstone: deleting a hosted version records its
/// <c>(org, ecosystem, purl_name, version)</c> coordinate, and republishing that coordinate is
/// refused under the same version-overwrite policy that would refuse overwriting the live
/// version. Without the tombstone, deleting first defeats a <c>block</c> policy outright,
/// because after the delete there is no row left to collide with.
///
/// Deletion runs through the real <see cref="PackageRepository.DeleteVersionAsync"/> — the method
/// every interactive delete path (management delete, npm unpublish, OCI manifest delete) calls —
/// so these tests pin the actual writer, not a hand-seeded tombstone row.
/// </summary>
[Trait("Category", "Unit")]
public sealed class VersionOverwriteTombstoneTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly InMemoryBlobStore _blobs = new();
    private readonly Microsoft.Extensions.Time.Testing.FakeTimeProvider _clock = TestTime.Frozen();

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o1', 'acme')");
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES ('o2', 'globex')");
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    // ---- the hole ----------------------------------------------------------------

    [Fact]
    public async Task DeleteThenRepublish_UnderBlockPolicy_Refused()
    {
        // Default org policy is 'block': a same-version push is a 409. Deleting the version
        // first used to launder that push into a fresh publish with different bytes.
        var svc = Build();
        var first = (PublishResult.Accepted)await svc.StoreAndRecordAsync(Sample());
        await DeleteAsync(first.VersionId);

        var republish = Sample() with { ArtifactBytes = new byte[] { 9, 9, 9, 9 } };
        var rej = Assert.IsType<PublishResult.Rejected>(await svc.StoreAndRecordAsync(republish));

        Assert.Equal(409, rej.HttpStatus);
        Assert.Equal("version_tombstoned", rej.Code);

        // Refused before any bytes were written: the only hosted blob is still the one the
        // first (accepted) publish stored, and no version row came back.
        Assert.Equal(new[] { first.BlobKey }, await HostedKeysAsync());
        await using var conn = await _db.OpenAsync();
        Assert.Equal(0, await conn.ExecuteScalarAsync<int>("SELECT COUNT(*) FROM package_versions"));
    }

    [Fact]
    public async Task DeleteThenRepublish_UnderBlockPolicy_RefusedByValidateDryRun()
    {
        // The bulk-import pre-validation surface projects the same refusal, so an operator is
        // never told a publish "would be accepted" that the real path will reject.
        var svc = Build();
        var first = (PublishResult.Accepted)await svc.StoreAndRecordAsync(Sample());
        await DeleteAsync(first.VersionId);

        var rej = Assert.IsType<PublishResult.Rejected>(await svc.ValidateAsync(Sample()));
        Assert.Equal(409, rej.HttpStatus);
        Assert.Equal("version_tombstoned", rej.Code);
    }

    [Fact]
    public async Task DeleteThenRepublish_Refused_EvenAfterParentPackageRowIsCollected()
    {
        // Deleting the last version GCs the packages row, so the coordinate has no package row
        // to hang off. The tombstone is keyed to the org, not the package, precisely so the
        // refusal survives that collection.
        var svc = Build();
        var packages = new PackageRepository(_db, time: _clock);
        var first = (PublishResult.Accepted)await svc.StoreAndRecordAsync(Sample());
        var pkg = await packages.GetByPurlNameAsync("o1", "npm", "lodash");
        await packages.DeleteVersionAsync(first.VersionId);
        Assert.True(await packages.DeletePackageIfEmptyAsync(pkg!.Id));
        Assert.Null(await packages.GetByPurlNameAsync("o1", "npm", "lodash"));

        var rej = Assert.IsType<PublishResult.Rejected>(await svc.StoreAndRecordAsync(Sample()));
        Assert.Equal("version_tombstoned", rej.Code);
    }

    [Fact]
    public async Task Delete_RecordsCoordinateDigestAndInjectedClock()
    {
        var svc = Build();
        var first = (PublishResult.Accepted)await svc.StoreAndRecordAsync(Sample());
        await DeleteAsync(first.VersionId);

        var tombstone = await new VersionTombstoneRepository(_db)
            .GetAsync("o1", "npm", "lodash", "1.0.0");

        Assert.NotNull(tombstone);
        Assert.Equal("o1", tombstone!.OrgId);
        Assert.Equal(first.Sha256, tombstone.ContentHash);
        // deleted_at comes from the injected TimeProvider, not the database wall clock.
        Assert.Equal(TestTime.KnownNow.ToUtcIso(), tombstone.DeletedAt);
    }

    // ---- adversarial twins: the fix must not break what already worked ------------

    [Fact]
    public async Task FirstPublish_WithNoPriorDelete_StillAccepted()
    {
        var svc = Build();
        Assert.IsType<PublishResult.Accepted>(await svc.StoreAndRecordAsync(Sample()));
    }

    [Fact]
    public async Task DeleteThenRepublish_UnderAllowPolicy_StillAccepted()
    {
        // An org that permits same-version pushes has always permitted delete-then-republish;
        // the tombstone is gated on the same policy, so nothing changes for it.
        await SetOverwritePolicyAsync("o1", "allow");
        var svc = Build();
        var first = (PublishResult.Accepted)await svc.StoreAndRecordAsync(Sample());
        await DeleteAsync(first.VersionId);

        var republished = Assert.IsType<PublishResult.Accepted>(
            await svc.StoreAndRecordAsync(Sample() with { ArtifactBytes = new byte[] { 7, 7, 7 } }));
        Assert.NotEqual(first.Sha256, republished.Sha256);
    }

    [Fact]
    public async Task DeleteThenRepublish_UnderExceptionPolicyWithPackageOverride_Accepted()
    {
        // The documented escape hatch: an org on 'exception' grants a specific package the
        // right to reuse coordinates. Changing either knob takes tenant:configure, which a
        // publish token does not hold — which is what makes it an override and not a bypass.
        await SetOverwritePolicyAsync("o1", "exception");
        var svc = Build();
        var packages = new PackageRepository(_db, time: _clock);
        var first = (PublishResult.Accepted)await svc.StoreAndRecordAsync(Sample());
        var pkg = await packages.GetByPurlNameAsync("o1", "npm", "lodash");
        await packages.SetSameVersionPushOverrideAsync(pkg!.Id, "o1", "allow");
        await packages.DeleteVersionAsync(first.VersionId);

        Assert.IsType<PublishResult.Accepted>(
            await svc.StoreAndRecordAsync(Sample() with { ArtifactBytes = new byte[] { 4, 4 } }));
    }

    [Fact]
    public async Task DeleteOneVersion_DifferentVersionOfSamePackage_StillAccepted()
    {
        // The tombstone is version-granular: deleting 1.0.0 must not block 1.0.1.
        var svc = Build();
        var first = (PublishResult.Accepted)await svc.StoreAndRecordAsync(Sample(version: "1.0.0"));
        await DeleteAsync(first.VersionId);

        Assert.IsType<PublishResult.Accepted>(await svc.StoreAndRecordAsync(Sample(version: "1.0.1")));
    }

    [Fact]
    public async Task DeleteInOneOrg_SameCoordinateInAnotherOrg_StillAccepted()
    {
        // Tenant isolation: o1's tombstone must not deny o2 a name+version it has never used.
        var svc = Build();
        var first = (PublishResult.Accepted)await svc.StoreAndRecordAsync(Sample());
        await DeleteAsync(first.VersionId);

        Assert.IsType<PublishResult.Accepted>(
            await svc.StoreAndRecordAsync(Sample() with { OrgId = "o2" }));
        // ...and o1 stays refused, so the twin is not passing because enforcement went away.
        Assert.Equal("version_tombstoned",
            Assert.IsType<PublishResult.Rejected>(await svc.StoreAndRecordAsync(Sample())).Code);
    }

    [Fact]
    public async Task ProxyOriginVersionDelete_LeavesNoTombstone()
    {
        // Cache-plane rows are fetched, not published. Evicting one must not spend the
        // coordinate — otherwise a proxy eviction would permanently block hosting that version.
        var svc = Build();
        var proxied = (PublishResult.Accepted)await svc.StoreAndRecordAsync(
            Sample(name: "left-pad") with { Origin = "proxy" });
        await DeleteAsync(proxied.VersionId);

        Assert.False(await new VersionTombstoneRepository(_db)
            .ExistsAsync("o1", "npm", "left-pad", "1.0.0"));
        Assert.IsType<PublishResult.Accepted>(await svc.StoreAndRecordAsync(Sample(name: "left-pad")));
    }

    [Fact]
    public async Task PublishRollbackDelete_LeavesNoTombstone()
    {
        // A rolled-back publish never became part of the visible version set; tombstoning it
        // would make the failure permanent and lock the publisher out of retrying.
        var svc = Build();
        var first = (PublishResult.Accepted)await svc.StoreAndRecordAsync(Sample());
        await new PackageRepository(_db, time: _clock)
            .DeleteVersionRowForPublishRollbackAsync(first.VersionId);

        Assert.False(await new VersionTombstoneRepository(_db)
            .ExistsAsync("o1", "npm", "lodash", "1.0.0"));
        Assert.IsType<PublishResult.Accepted>(await svc.StoreAndRecordAsync(Sample()));
    }

    // ---- harness -----------------------------------------------------------------

    private Task DeleteAsync(string versionId)
        => new PackageRepository(_db, time: _clock).DeleteVersionAsync(versionId);

    private async Task SetOverwritePolicyAsync(string orgId, string policy)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO org_settings (org_id, version_overwrite_policy) VALUES (@orgId, @policy)",
            new { orgId, policy });
    }

    private async Task<List<string>> HostedKeysAsync()
    {
        var keys = new List<string>();
        await foreach (var blob in _blobs.ListAsync("hosted/"))
        {
            keys.Add(blob.Key);
        }
        return keys;
    }

    private PackagePublishService Build()
    {
        var packages = new PackageRepository(_db, time: _clock);
        var audit = new AuditRepository(_db);
        var cfg = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["CLAIM_ENFORCEMENT"] = "off" })
            .Build();
        var resolver = new ClaimResolver(new ClaimRepository(_db), new AirGapMode(cfg));
        var emitter = new Dependably.Infrastructure.Audit.AuditEmitter(
            new Dependably.Infrastructure.Audit.AuditEventRepository(_db),
            new Microsoft.AspNetCore.Http.HttpContextAccessor(),
            NullLogger<Dependably.Infrastructure.Audit.AuditEmitter>.Instance, cfg,
            new ServiceCollection().BuildServiceProvider(),
            new OrgRepository(_db), _clock);
        var storage = new GlobalTenantStorageResolver(_db, new TieredBlobStorage(_blobs, _blobs));
        var scanner = new VulnerabilityScanService(new VulnerabilityScanService.Dependencies(
            _db, TestOsvSource.Create(),
            new VulnerabilityRepository(_db, _clock), audit, cfg,
            new AirGapMode(cfg),
            NullLogger<VulnerabilityScanService>.Instance,
            _clock,
            new OrgRepository(_db),
            Substitute.For<IPackageEventSink>(), new InProcessDistributedLock(TimeProvider.System),
            TestAlerts.NoOp(_db, _clock)));
        return new PackagePublishService(
            packages, new PackageVersionFilesRepository(_db), new OrgRepository(_db), storage,
            new PublishGate(cfg, resolver),
            new NameBindingGate(cfg, new NameBindingRepository(_db), NullLogger<NameBindingGate>.Instance),
            new VersionTombstoneRepository(_db),
            new Dependably.Infrastructure.Edge.EdgePublishGuard(TestEdgeMode.Disabled()),
            new PublishAuditor(audit, emitter), scanner,
            new LicenseRepository(_db, _clock, TestNormalizers.License(_db)),
            NullLogger<PackagePublishService>.Instance);
    }

    private static PublishRequest Sample(string name = "lodash", string version = "1.0.0") => new()
    {
        OrgId = "o1",
        Ecosystem = "npm",
        Name = name,
        PurlName = name,
        Version = version,
        Filename = $"{name}-{version}.tgz",
        Purl = $"pkg:npm/{name}@{version}",
        ArtifactBytes = new byte[64],
        Origin = "uploaded",
        SizeCap = long.MaxValue,
        ActorUserId = "u1",
    };
}
