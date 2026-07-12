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

[Trait("Category", "Unit")]
public sealed class PackagePublishServiceTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly InMemoryBlobStore _blobs = new();
    private readonly Microsoft.Extensions.Time.Testing.FakeTimeProvider _clock = TestTime.Frozen();
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
            // SIEM queue is opt-in; empty service provider yields a null forwarder
            // and the emit path becomes a no-op for SIEM, which is correct for unit tests.
            new Microsoft.Extensions.DependencyInjection.ServiceCollection().BuildServiceProvider(),
            new OrgRepository(_db), _clock);
        // Tier-shared bootstrap: PackagePublishService writes to Registry; in unit tests
        // both tiers point to the same in-memory store. Wrap in the community resolver so
        // the status + provisioning gates run on the real path.
        var tiered = new TieredBlobStorage(_blobs, _blobs);
        var storage = new GlobalTenantStorageResolver(_db, tiered);
        // Post-publish vuln scan runs synchronously; route it at a recording test double so
        // we can assert it fired (and so individual tests can swap it for a throwing variant).
        _osv = new RecordingOsvSource();
        var scanner = new VulnerabilityScanService(new VulnerabilityScanService.Dependencies(
            _db, _osv,
            new VulnerabilityRepository(_db, _clock), audit, cfg,
            new NoAirGap(),
            NullLogger<VulnerabilityScanService>.Instance,
            _clock,
            new OrgRepository(_db),
            Substitute.For<IPackageEventSink>(), new InProcessDistributedLock(TimeProvider.System),
            Dependably.Tests.Infrastructure.TestAlerts.NoOp(_db, _clock)));
        var auditor = new Dependably.Infrastructure.Publish.PublishAuditor(audit, emitter);
        var licenses = new LicenseRepository(_db, _clock, TestNormalizers.License(_db));
        return new PackagePublishService(packages, new PackageVersionFilesRepository(_db), new OrgRepository(_db), storage, gate,
            new Dependably.Infrastructure.Edge.EdgePublishGuard(TestEdgeMode.Disabled()),
            auditor, scanner, licenses, NullLogger<PackagePublishService>.Instance);
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

    [Theory]
    [InlineData("a/b")]            // unscoped npm name with a slash
    [InlineData("@scope/a/b")]     // scoped shape with an extra segment
    [InlineData("@/name")]         // empty scope
    [InlineData("@scope/")]        // empty plain segment
    [InlineData(@"a\b")]           // backslash separator
    public async Task NpmName_NonScopedSeparator_RejectedWith422(string badName)
    {
        // Only the single leading '@scope/' shape may carry a slash; anything else would
        // inject extra segments into the hosted blob key.
        var svc = Build();
        var rej = Assert.IsType<PublishResult.Rejected>(
            await svc.StoreAndRecordAsync(Sample(name: badName)));
        Assert.Equal(422, rej.HttpStatus);
        Assert.Equal("path_unsafe", rej.Code);
    }

    [Theory]
    [InlineData("pypi")]
    [InlineData("nuget")]
    [InlineData("rpm")]
    [InlineData("maven")]
    public async Task NonNpmName_WithSlash_RejectedWith422(string ecosystem)
    {
        // The '@scope/' allowance is npm-only; every other ecosystem's name is a single
        // blob-key segment, so any separator rejects — including the scoped-looking shape.
        var svc = Build();
        var req = Sample(name: "@scope/name") with { Ecosystem = ecosystem };
        var rej = Assert.IsType<PublishResult.Rejected>(await svc.StoreAndRecordAsync(req));
        Assert.Equal(422, rej.HttpStatus);
        Assert.Equal("path_unsafe", rej.Code);
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
            OccurredAt = TestTime.KnownNow,
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
        // Org policy must permit overwrites for this test — set version_overwrite_policy to 'allow'.
        await using (var setup = await _db.OpenAsync())
        {
            await setup.ExecuteAsync(
                "INSERT INTO org_settings (org_id, version_overwrite_policy, allow_version_overwrite) VALUES ('o1', 'allow', 1)");
        }
        var svc = Build();
        var first = Sample(version: "1.0.0");
        var firstResult = (PublishResult.Accepted)await svc.StoreAndRecordAsync(first);
        string firstHash = firstResult.Sha256;

        // Different bytes → different hash → real overwrite.
        var second = first with { ArtifactBytes = new byte[] { 1, 2, 3, 4, 5 }, AllowOverwrite = true };
        var secondResult = await svc.StoreAndRecordAsync(second);
        var accepted = Assert.IsType<PublishResult.Accepted>(secondResult);

        // VersionId is preserved across an overwrite (existing FKs don't get re-stitched).
        Assert.Equal(firstResult.VersionId, accepted.VersionId);
        Assert.NotEqual(firstHash, accepted.Sha256);

        // package.replace is a per-version operator action — it belongs in `activity`,
        // not `audit_log`.
        await using var conn = await _db.OpenAsync();
        var replaceRows = (await conn.QueryAsync<(string EventType, string Detail)>(
            "SELECT event_type, detail FROM activity WHERE org_id = 'o1' AND event_type = 'package.replace'"))
            .ToList();
        Assert.Single(replaceRows);
        Assert.Contains("sha256:" + firstHash, replaceRows[0].Detail);
        Assert.Contains("sha256:" + accepted.Sha256, replaceRows[0].Detail);
    }

    [Fact]
    public async Task Pypi_DifferentFilename_SameVersion_StoredAsSecondFile_WheelUntouched()
    {
        // Multi-file model: a wheel already exists for this version; the sdist arriving for
        // the SAME version (different filename) joins the release as its own file record and
        // blob. The wheel's blob and the version row's primary columns stay untouched — the
        // historical corruption (blob_key silently repointed at the sdist while the row kept
        // advertising the wheel's filename) is structurally impossible now.
        await using (var setup = await _db.OpenAsync())
        {
            await setup.ExecuteAsync(
                "INSERT INTO org_settings (org_id, version_overwrite_policy, allow_version_overwrite) VALUES ('o1', 'allow', 1)");
        }
        var svc = Build();
        var wheel = Sample(name: "acme-pkg", version: "1.2.1") with
        {
            Ecosystem = "pypi",
            Filename = "acme_pkg-1.2.1-py3-none-any.whl",
        };
        Assert.IsType<PublishResult.Accepted>(await svc.StoreAndRecordAsync(wheel));

        var sdist = wheel with { Filename = "acme_pkg-1.2.1.tar.gz", AllowOverwrite = true };
        Assert.IsType<PublishResult.Accepted>(await svc.StoreAndRecordAsync(sdist));

        // Both blobs exist under their own keys; the version row still points at the wheel.
        Assert.True(await _blobs.ExistsAsync(
            BlobKeys.Hosted("o1", "pypi", "acme-pkg", "1.2.1", "acme_pkg-1.2.1-py3-none-any.whl")));
        Assert.True(await _blobs.ExistsAsync(
            BlobKeys.Hosted("o1", "pypi", "acme-pkg", "1.2.1", "acme_pkg-1.2.1.tar.gz")));
        var packages = new PackageRepository(_db);
        var pkg = await packages.GetByPurlNameAsync("o1", "pypi", "acme-pkg");
        var version = await packages.GetVersionAsync(pkg!.Id, "1.2.1");
        Assert.EndsWith("acme_pkg-1.2.1-py3-none-any.whl", version!.BlobKey);
    }

    [Fact]
    public async Task NonPypi_DifferentFilename_SameVersion_StillRejectedWithArtifactMismatch()
    {
        // The one-artifact-per-version guard remains for every other ecosystem: a
        // differently-named artifact for an existing version must be rejected outright,
        // even when the org policy permits same-filename overwrites.
        await using (var setup = await _db.OpenAsync())
        {
            await setup.ExecuteAsync(
                "INSERT INTO org_settings (org_id, version_overwrite_policy, allow_version_overwrite) VALUES ('o1', 'allow', 1)");
        }
        var svc = Build();
        var first = Sample(name: "acme-npm-guard", version: "1.2.1");
        Assert.IsType<PublishResult.Accepted>(await svc.StoreAndRecordAsync(first));

        var renamed = first with { Filename = "acme-npm-guard-1.2.1-alt.tgz", AllowOverwrite = true };
        var rej = Assert.IsType<PublishResult.Rejected>(await svc.StoreAndRecordAsync(renamed));
        Assert.Equal(409, rej.HttpStatus);
        Assert.Equal("artifact_mismatch", rej.Code);

        Assert.False(await _blobs.ExistsAsync(
            BlobKeys.Hosted("o1", "npm", "acme-npm-guard", "1.2.1", "acme-npm-guard-1.2.1-alt.tgz")));
    }

    [Fact]
    public async Task SameFilename_SameVersion_OverwriteAllowed_StillOverwrites()
    {
        // Regression guard: the new artifact-mismatch check must not interfere with the
        // existing same-filename overwrite path (a genuine re-push of the identical artifact).
        await using (var setup = await _db.OpenAsync())
        {
            await setup.ExecuteAsync(
                "INSERT INTO org_settings (org_id, version_overwrite_policy, allow_version_overwrite) VALUES ('o1', 'allow', 1)");
        }
        var svc = Build();
        var first = Sample(name: "acme-resame", version: "1.0.0");
        var firstResult = (PublishResult.Accepted)await svc.StoreAndRecordAsync(first);

        var second = first with { ArtifactBytes = new byte[] { 9, 9, 9 }, AllowOverwrite = true };
        var secondResult = await svc.StoreAndRecordAsync(second);
        var accepted = Assert.IsType<PublishResult.Accepted>(secondResult);
        Assert.Equal(firstResult.VersionId, accepted.VersionId);
    }

    [Fact]
    public async Task ValidateAsync_DryRunParity_PypiSecondFileAccepted_NonPypiMismatchRejected()
    {
        // Dry-run parity: the bulk-import pre-flight surface must report exactly what the
        // real publish path would do — a PyPI sdist joining an existing wheel is accepted
        // (new file of the release); a renamed non-PyPI artifact stays artifact_mismatch.
        await using (var setup = await _db.OpenAsync())
        {
            await setup.ExecuteAsync(
                "INSERT INTO org_settings (org_id, version_overwrite_policy, allow_version_overwrite) VALUES ('o1', 'allow', 1)");
        }
        var svc = Build();
        var wheel = Sample(name: "acme-dryrun", version: "1.0.0") with
        {
            Ecosystem = "pypi",
            Filename = "acme_dryrun-1.0.0-py3-none-any.whl",
        };
        await svc.StoreAndRecordAsync(wheel);

        var sdistDryRun = wheel with { Filename = "acme_dryrun-1.0.0.tar.gz", AllowOverwrite = true };
        Assert.IsType<PublishResult.Accepted>(await svc.ValidateAsync(sdistDryRun));

        var npmFirst = Sample(name: "acme-dryrun-npm", version: "1.0.0");
        await svc.StoreAndRecordAsync(npmFirst);
        var npmRenamed = npmFirst with { Filename = "acme-dryrun-npm-1.0.0-alt.tgz", AllowOverwrite = true };
        var rej = Assert.IsType<PublishResult.Rejected>(await svc.ValidateAsync(npmRenamed));
        Assert.Equal(409, rej.HttpStatus);
        Assert.Equal("artifact_mismatch", rej.Code);
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
        long count = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM activity WHERE org_id = 'o1' AND event_type = 'package.replace' AND purl LIKE '%fresh-pkg%'");
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
        long auditCount = await conn.ExecuteScalarAsync<long>(
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
        string? checkedAt = await conn.ExecuteScalarAsync<string?>(
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
        long versionCount = await conn.ExecuteScalarAsync<long>(
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
        long versionCount = await conn.ExecuteScalarAsync<long>(
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

    // ── Per-tenant storage quota ────────────────────────────────────────────────

    [Fact]
    public async Task Quota_NullQuota_NeverRejects()
    {
        // Default state: storage_quota_bytes is NULL → unlimited. Single-tenant installs and
        // unconfigured multi-tenant deployments must publish without ever computing usage.
        var svc = Build();
        var result = await svc.StoreAndRecordAsync(Sample(version: "1.0.0", size: 10_000_000));
        Assert.IsType<PublishResult.Accepted>(result);
    }

    [Fact]
    public async Task Quota_UnderCap_Accepts()
    {
        var orgs = new OrgRepository(_db);
        await orgs.SetStorageQuotaBytesAsync("o1", 1_000);
        var svc = Build();

        var result = await svc.StoreAndRecordAsync(Sample(version: "1.0.0", size: 500));
        Assert.IsType<PublishResult.Accepted>(result);
    }

    [Fact]
    public async Task Quota_NextPublishWouldExceed_RejectsWith413()
    {
        var orgs = new OrgRepository(_db);
        await orgs.SetStorageQuotaBytesAsync("o1", 1_000);
        var svc = Build();

        Assert.IsType<PublishResult.Accepted>(await svc.StoreAndRecordAsync(Sample(name: "a", version: "1.0.0", size: 600)));
        var second = await svc.StoreAndRecordAsync(Sample(name: "b", version: "1.0.0", size: 600));

        var rej = Assert.IsType<PublishResult.Rejected>(second);
        Assert.Equal(413, rej.HttpStatus);
        Assert.Equal("tenant_quota_exceeded", rej.Code);
        // The reject must happen BEFORE the blob put — orphan bytes from rejected publishes
        // would defeat the whole point of the quota.
        Assert.False(await _blobs.ExistsAsync(BlobKeys.Hosted("o1", "npm", "b", "1.0.0", "b-1.0.0.tgz")));
    }

    [Fact]
    public async Task Quota_Overwrite_CountsOnlyNetDelta()
    {
        // An overwrite must not double-count the artefact's existing size. Two consecutive
        // 600-byte writes of the SAME version under a 1000-byte cap would otherwise reject
        // the second — but a 600 → 700 overwrite is only +100 against the cap.
        // Org policy must permit overwrites.
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO org_settings (org_id, version_overwrite_policy, allow_version_overwrite) VALUES ('o1', 'allow', 1)");
        }
        var orgs = new OrgRepository(_db);
        await orgs.SetStorageQuotaBytesAsync("o1", 1_000);
        var svc = Build();

        Assert.IsType<PublishResult.Accepted>(await svc.StoreAndRecordAsync(Sample(version: "1.0.0", size: 600)));
        var grow = Sample(version: "1.0.0", size: 700) with { AllowOverwrite = true };
        var second = await svc.StoreAndRecordAsync(grow);
        Assert.IsType<PublishResult.Accepted>(second);
    }

    [Fact]
    public async Task Quota_OverwriteThatStillExceeds_Rejects()
    {
        // Edge of the delta logic: prior 600 + (1500-600 delta) = 1500 > 1000 cap → reject.
        // Org policy must permit overwrites so the quota gate (not policy gate) is the one rejecting.
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO org_settings (org_id, version_overwrite_policy, allow_version_overwrite) VALUES ('o1', 'allow', 1)");
        }
        var orgs = new OrgRepository(_db);
        await orgs.SetStorageQuotaBytesAsync("o1", 1_000);
        var svc = Build();

        Assert.IsType<PublishResult.Accepted>(await svc.StoreAndRecordAsync(Sample(version: "1.0.0", size: 600)));
        var grow = Sample(version: "1.0.0", size: 1_500) with { AllowOverwrite = true };
        var rej = Assert.IsType<PublishResult.Rejected>(await svc.StoreAndRecordAsync(grow));
        Assert.Equal(413, rej.HttpStatus);
        Assert.Equal("tenant_quota_exceeded", rej.Code);
    }

    [Fact]
    public async Task Quota_InstanceDefault_AppliesWhenTenantHasNoOverride()
    {
        // Instance-level default_storage_quota_bytes blocks a tenant with no explicit cap
        // when the combined usage would exceed the instance default.
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO instance_settings (key, value) VALUES ('default_storage_quota_bytes', '1000') ON CONFLICT(key) DO UPDATE SET value = '1000'");

        var svc = Build();
        Assert.IsType<PublishResult.Accepted>(await svc.StoreAndRecordAsync(Sample(name: "a", version: "1.0.0", size: 600)));
        var second = await svc.StoreAndRecordAsync(Sample(name: "b", version: "1.0.0", size: 600));

        var rej = Assert.IsType<PublishResult.Rejected>(second);
        Assert.Equal(413, rej.HttpStatus);
        Assert.Equal("tenant_quota_exceeded", rej.Code);
    }

    [Fact]
    public async Task Quota_TenantExplicitOverridesInstanceDefault()
    {
        // Tenant-set quota takes precedence: tenant is 5000 bytes while instance default is
        // only 200. The publish must use the tenant-specific cap.
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO instance_settings (key, value) VALUES ('default_storage_quota_bytes', '200') ON CONFLICT(key) DO UPDATE SET value = '200'");

        var orgs = new OrgRepository(_db);
        await orgs.SetStorageQuotaBytesAsync("o1", 5_000);

        var svc = Build();
        // 3 × 600-byte publishes = 1800 bytes — over the 200-byte instance default but
        // under the 5000-byte tenant override. All three must be accepted.
        Assert.IsType<PublishResult.Accepted>(await svc.StoreAndRecordAsync(Sample(name: "a", version: "1.0.0", size: 600)));
        Assert.IsType<PublishResult.Accepted>(await svc.StoreAndRecordAsync(Sample(name: "b", version: "1.0.0", size: 600)));
        Assert.IsType<PublishResult.Accepted>(await svc.StoreAndRecordAsync(Sample(name: "c", version: "1.0.0", size: 600)));
    }

    [Fact]
    public async Task Quota_NoInstanceDefault_UnlimitedWhenTenantAlsoUnset()
    {
        // Neither instance nor tenant quota set — must remain unlimited (back-compat).
        var svc = Build();
        var result = await svc.StoreAndRecordAsync(Sample(version: "1.0.0", size: 50_000_000));
        Assert.IsType<PublishResult.Accepted>(result);
    }

    // ── Transactional compensation on metadata failure ──────────────────────────

    // ── Path-safety branches inside Name / PurlName ─────────────────────────────

    [Fact]
    public async Task Name_WithDoubleDot_RejectedAsPathUnsafe()
    {
        // The filename / version path-safety pass uses PathSafeValidator (covered already),
        // but Name and PurlName bypass that path because npm scoped names legitimately
        // contain a slash. They still need a traversal guard — covered by the dedicated
        // '..' / NUL check at the tail of ValidatePathSafety.
        var svc = Build();
        var rej = Assert.IsType<PublishResult.Rejected>(
            await svc.StoreAndRecordAsync(Sample(name: "weird..name")));
        Assert.Equal(422, rej.HttpStatus);
        Assert.Equal("path_unsafe", rej.Code);
        Assert.Contains("..", rej.Message);
    }

    [Fact]
    public async Task PurlName_WithNullByte_RejectedAsPathUnsafe()
    {
        // PurlName carries the canonical lookup form; a NUL byte there is the classic
        // path-truncation attack on POSIX. ValidatePathSafety must reject regardless of
        // whether Name is clean.
        var svc = Build();
        var req = Sample() with { PurlName = "lodash\0evil" };
        var rej = Assert.IsType<PublishResult.Rejected>(await svc.StoreAndRecordAsync(req));
        Assert.Equal(422, rej.HttpStatus);
        Assert.Equal("path_unsafe", rej.Code);
    }

    // ── ValidateAsync branch gaps ───────────────────────────────────────────────

    [Fact]
    public async Task ValidateAsync_ClaimEnforcementOn_UnclaimedName_Rejects409()
    {
        // Dry-run must surface the same claim_required rejection the real path emits, so
        // bulk-import callers don't get a green pre-flight followed by a runtime 409.
        var svc = Build(claimEnforcement: "on");
        var rej = Assert.IsType<PublishResult.Rejected>(
            await svc.ValidateAsync(Sample(name: "unclaimed-validate-pkg")));
        Assert.Equal(409, rej.HttpStatus);
        Assert.Equal("claim_required", rej.Code);
    }

    [Fact]
    public async Task ValidateAsync_ExistingPackage_NewVersion_AcceptsAndDoesNotWrite()
    {
        // Package row exists (seeded by a prior real publish) but the version we're
        // validating doesn't. The dry-run must fall through the `if (pkg is not null)`
        // block — the inner `if (existing is not null)` is false — and report Accepted
        // without writing anything.
        var svc = Build();
        await svc.StoreAndRecordAsync(Sample(version: "1.0.0"));

        var result = await svc.ValidateAsync(Sample(version: "2.0.0"));
        var accepted = Assert.IsType<PublishResult.Accepted>(result);
        Assert.Equal("", accepted.VersionId);

        // The version row for 2.0.0 must NOT have been created.
        await using var conn = await _db.OpenAsync();
        long count = await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(*) FROM package_versions WHERE purl = 'pkg:npm/lodash@2.0.0'");
        Assert.Equal(0, count);
    }

    // ── CommitMetadataAsync failure branches ────────────────────────────────────

    [Fact]
    public async Task InsertFails_CompensatingDeleteAlsoThrows_OriginalExceptionStillPropagates()
    {
        // Force the INSERT-path failure with a registry that drops the package_versions table
        // inside PutAsync (so the put commits but the subsequent INSERT throws 'no such table'),
        // then make the compensating delete throw too — exercising the inner catch on the
        // compensating delete (lines 211-216 in the SUT). The outer exception must still
        // propagate; the operator-visible signal that something needs reconciliation is
        // the logged 'Compensating blob delete failed' error.
        var failingDelete = new DropTableOnPutBlobStore(_blobs, _db, "package_versions", throwOnDelete: true);
        var svc = BuildWithRegistry(failingDelete);

        var ex = await Assert.ThrowsAnyAsync<Exception>(() => svc.StoreAndRecordAsync(Sample()));
        Assert.NotNull(ex);
        // The wrapped delete attempt must have been made — that's how we know the
        // compensating-delete branch ran (and threw, exercising the inner catch).
        Assert.True(failingDelete.DeleteAttempted,
            "Compensating delete must have been attempted on the INSERT failure path.");
    }

    [Fact]
    public async Task OverwriteFails_MetadataUpdateThrows_NoCompensatingDelete()
    {
        // OVERWRITE-path failure (lines 219-227 in the SUT): the put already replaced
        // bytes in place, so the compensating delete is *intentionally* suppressed —
        // a delete here would erase the new bytes too, leaving the row pointing at a
        // missing key. Verify both halves: the exception propagates AND DeleteAsync is
        // never called.
        //
        // Force the update to fail by side-loading a DROP TABLE inside the registry's
        // PutAsync. Sequence inside the SUT: GetVersionAsync (table still there) →
        // SHA256 → GetRegistryAsync → PutAsync (drops the table) → UpdateVersionForOverwriteAsync
        // (SQL error, 'no such table').
        // Org policy must permit overwrites so the overwrite path is reached.
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO org_settings (org_id, version_overwrite_policy, allow_version_overwrite) VALUES ('o1', 'allow', 1)");
        }
        var svc = BuildWithRegistry(_blobs);
        await svc.StoreAndRecordAsync(Sample(version: "1.0.0", size: 100));

        // Now wire the dropping registry for the overwrite attempt.
        var droppingRegistry = new DropTableOnPutBlobStore(_blobs, _db, "package_versions");
        var svcWithSabotage = BuildWithRegistry(droppingRegistry);

        var overwrite = Sample(version: "1.0.0", size: 200) with { AllowOverwrite = true };
        await Assert.ThrowsAnyAsync<Exception>(() => svcWithSabotage.StoreAndRecordAsync(overwrite));

        // The OVERWRITE branch must NOT compensate by deleting the blob.
        Assert.False(droppingRegistry.DeleteAttempted,
            "OVERWRITE failure must not trigger a compensating blob delete; the put was destructive.");
    }

    // ── Original orphan-delete test (kept) ──────────────────────────────────────

    [Fact]
    public async Task BlobPutSucceedsButVersionInsertFails_CompensatesByDeletingOrphanBlob()
    {
        // Force CreateVersionAsync to throw after the blob put has committed: a registry whose
        // PutAsync drops the package_versions table, so the put succeeds but the subsequent
        // INSERT fails with 'no such table'. The dedup check ran earlier (table still present),
        // so the flow passes the put and fails inside CreateVersionAsync — exactly the
        // orphan-blob scenario the compensating-delete catch is there to handle.
        var droppingRegistry = new DropTableOnPutBlobStore(_blobs, _db, "package_versions");
        var svc = BuildWithRegistry(droppingRegistry);
        string blobKey = BlobKeys.Hosted("o1", "npm", "lodash", "1.0.0", "lodash-1.0.0.tgz");

        await Assert.ThrowsAnyAsync<Exception>(() => svc.StoreAndRecordAsync(Sample()));

        // The compensating delete must have run; otherwise we'd have an orphan blob with
        // no row pointing at it — the very scenario the catch guards against.
        Assert.True(droppingRegistry.DeleteAttempted,
            "INSERT failure must trigger a compensating blob delete; orphan would otherwise persist.");
        Assert.False(await _blobs.ExistsAsync(blobKey),
            "INSERT failure must trigger a compensating blob delete; orphan would otherwise persist.");
    }

    // Same wiring as Build(), parameterised on the registry-tier blob store so tests can
    // route writes through a failing/sabotaging double. Cache tier stays on the shared
    // in-memory store; PackagePublishService only touches the registry tier.
    private PackagePublishService BuildWithRegistry(IBlobStore registry, string claimEnforcement = "off")
    {
        var packages = new PackageRepository(_db);
        var audit = new AuditRepository(_db);
        var cfg = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["CLAIM_ENFORCEMENT"] = claimEnforcement })
            .Build();
        var resolver = new ClaimResolver(new ClaimRepository(_db), new AirGapMode(cfg));
        var gate = new PublishGate(cfg, resolver);
        var emitter = new Dependably.Infrastructure.Audit.AuditEmitter(
            new Dependably.Infrastructure.Audit.AuditEventRepository(_db),
            new Microsoft.AspNetCore.Http.HttpContextAccessor(),
            NullLogger<Dependably.Infrastructure.Audit.AuditEmitter>.Instance, cfg,
            new Microsoft.Extensions.DependencyInjection.ServiceCollection().BuildServiceProvider(),
            new OrgRepository(_db), _clock);
        var tiered = new TieredBlobStorage(_blobs, registry);
        var storage = new GlobalTenantStorageResolver(_db, tiered);
        _osv ??= new RecordingOsvSource();
        var scanner = new VulnerabilityScanService(new VulnerabilityScanService.Dependencies(
            _db, _osv,
            new VulnerabilityRepository(_db, _clock), audit, cfg,
            new NoAirGap(),
            NullLogger<VulnerabilityScanService>.Instance,
            _clock,
            new OrgRepository(_db),
            Substitute.For<IPackageEventSink>(), new InProcessDistributedLock(TimeProvider.System),
            Dependably.Tests.Infrastructure.TestAlerts.NoOp(_db, _clock)));
        var auditor = new Dependably.Infrastructure.Publish.PublishAuditor(audit, emitter);
        var licenses = new LicenseRepository(_db, _clock, TestNormalizers.License(_db));
        return new PackagePublishService(packages, new PackageVersionFilesRepository(_db), new OrgRepository(_db), storage, gate,
            new Dependably.Infrastructure.Edge.EdgePublishGuard(TestEdgeMode.Disabled()),
            auditor, scanner, licenses, NullLogger<PackagePublishService>.Instance);
    }

    /// <summary>
    /// Blob store that drops a named DB table inside PutAsync, then delegates to the inner
    /// store. Used to force a DB write to throw after the blob put has already committed —
    /// either the INSERT-failure scenario (orphan blob; the SUT's catch at lines 211-216
    /// compensates) or the OVERWRITE-failure scenario (lines 219-227 log and re-throw without
    /// compensating). Tracks whether DeleteAsync was attempted so a test can assert whether the
    /// branch compensated. When <paramref name="throwOnDelete"/> is set, DeleteAsync throws,
    /// exercising the inner catch around the compensating delete.
    /// </summary>
    private sealed class DropTableOnPutBlobStore : IBlobStore
    {
        private readonly IBlobStore _inner;
        private readonly IMetadataStore _db;
        private readonly string _table;
        private readonly bool _throwOnDelete;
        public bool DeleteAttempted { get; private set; }
        public DropTableOnPutBlobStore(IBlobStore inner, IMetadataStore db, string table, bool throwOnDelete = false)
        {
            _inner = inner;
            _db = db;
            _table = table;
            _throwOnDelete = throwOnDelete;
        }
        public async Task PutAsync(string key, Stream data, CancellationToken ct = default)
        {
            await using (var conn = await _db.OpenAsync(ct))
            {
                await conn.ExecuteAsync($"DROP TABLE {_table}");
            }
            await _inner.PutAsync(key, data, ct);
        }
        public Task<Stream?> GetAsync(string key, CancellationToken ct = default) => _inner.GetAsync(key, ct);
        public Task<RangedStream?> GetRangeAsync(string key, long from, long to, CancellationToken ct = default) => _inner.GetRangeAsync(key, from, to, ct);
        public Task<bool> ExistsAsync(string key, CancellationToken ct = default) => _inner.ExistsAsync(key, ct);
        public Task DeleteAsync(string key, CancellationToken ct = default)
        {
            DeleteAttempted = true;
            return _throwOnDelete ? throw new InvalidOperationException("simulated blob delete outage") : _inner.DeleteAsync(key, ct);
        }
        public Task<long> GetTotalSizeAsync(CancellationToken ct = default) => _inner.GetTotalSizeAsync(ct);
        public IAsyncEnumerable<BlobInfo> ListAsync(string prefix, CancellationToken ct = default) => _inner.ListAsync(prefix, ct);
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

    private sealed class NoAirGap : IAirGapMode
    {
        public bool IsEnabled => false;
        public IReadOnlySet<string> DisabledJobs => new System.Collections.Generic.HashSet<string>();
        public bool IsJobDisabled(string jobName) => false;
    }

    // ── PyPI multi-file-per-version ──────────────────────────────────────────

    private static PublishRequest PypiSample(string name, string version, string filename, long size = 100) => new()
    {
        OrgId = "o1",
        Ecosystem = "pypi",
        Name = name,
        PurlName = name,
        Version = version,
        Filename = filename,
        Purl = $"pkg:pypi/{name}@{version}",
        ArtifactBytes = new byte[size],
        Origin = "uploaded",
        SizeCap = long.MaxValue,
        ActorUserId = "u1",
    };

    [Fact]
    public async Task Pypi_SecondFileForSameVersion_AcceptedUnderBlockPolicy_AndSizeSumsOnVersionRow()
    {
        // The org default overwrite policy is 'block': the sdist joining the wheel is a NEW
        // file of the release, not an overwrite, so it must be accepted anyway.
        var svc = Build();
        var wheel = PypiSample("mfpkg", "1.0.0", "mfpkg-1.0.0-py3-none-any.whl", size: 100);
        Assert.IsType<PublishResult.Accepted>(await svc.StoreAndRecordAsync(wheel));

        var sdist = PypiSample("mfpkg", "1.0.0", "mfpkg-1.0.0.tar.gz", size: 40);
        Assert.IsType<PublishResult.Accepted>(await svc.StoreAndRecordAsync(sdist));

        var packages = new PackageRepository(_db);
        var pkg = await packages.GetByPurlNameAsync("o1", "pypi", "mfpkg");
        var version = await packages.GetVersionAsync(pkg!.Id, "1.0.0");
        var files = await new PackageVersionFilesRepository(_db).GetByVersionAsync(version!.Id);

        Assert.Equal(2, files.Count);
        Assert.Contains(files, f => f.Filename == "mfpkg-1.0.0-py3-none-any.whl" && f.SizeBytes == 100);
        Assert.Contains(files, f => f.Filename == "mfpkg-1.0.0.tar.gz" && f.SizeBytes == 40);
        // The version row carries the SUM of its files so quota release on delete is symmetric.
        Assert.Equal(140, version.SizeBytes);
        // Both blobs stored under distinct hosted keys.
        Assert.True(await _blobs.ExistsAsync(BlobKeys.Hosted("o1", "pypi", "mfpkg", "1.0.0", "mfpkg-1.0.0-py3-none-any.whl")));
        Assert.True(await _blobs.ExistsAsync(BlobKeys.Hosted("o1", "pypi", "mfpkg", "1.0.0", "mfpkg-1.0.0.tar.gz")));
    }

    [Fact]
    public async Task Pypi_SameFilenameReupload_StaysPolicyGated()
    {
        // Re-uploading a filename the release already holds IS an overwrite: the default
        // 'block' policy must reject it even though multi-file additions are allowed.
        var svc = Build();
        var wheel = PypiSample("mfgate", "1.0.0", "mfgate-1.0.0-py3-none-any.whl");
        Assert.IsType<PublishResult.Accepted>(await svc.StoreAndRecordAsync(wheel));

        var rej = Assert.IsType<PublishResult.Rejected>(await svc.StoreAndRecordAsync(wheel));
        Assert.Equal(409, rej.HttpStatus);
        Assert.Equal("version_exists", rej.Code);
    }

    [Fact]
    public async Task Pypi_SameFilenameOverwrite_AllowedPolicy_UpdatesFileRecordAndSum()
    {
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO org_settings (org_id, version_overwrite_policy, allow_version_overwrite) VALUES ('o1', 'allow', 1)");
        }

        var svc = Build();
        var wheel = PypiSample("mfow", "1.0.0", "mfow-1.0.0-py3-none-any.whl", size: 100);
        Assert.IsType<PublishResult.Accepted>(await svc.StoreAndRecordAsync(wheel));
        var sdist = PypiSample("mfow", "1.0.0", "mfow-1.0.0.tar.gz", size: 40);
        Assert.IsType<PublishResult.Accepted>(await svc.StoreAndRecordAsync(sdist));

        // Overwrite the NON-primary file (the sdist) with different bytes.
        var sdist2 = PypiSample("mfow", "1.0.0", "mfow-1.0.0.tar.gz", size: 60);
        sdist2.ArtifactBytes![0] = 0xFF;
        var accepted = Assert.IsType<PublishResult.Accepted>(await svc.StoreAndRecordAsync(sdist2));

        var packages = new PackageRepository(_db);
        var pkg = await packages.GetByPurlNameAsync("o1", "pypi", "mfow");
        var version = await packages.GetVersionAsync(pkg!.Id, "1.0.0");
        var files = await new PackageVersionFilesRepository(_db).GetByVersionAsync(version!.Id);

        Assert.Equal(2, files.Count);
        var sdistFile = files.Single(f => f.Filename == "mfow-1.0.0.tar.gz");
        Assert.Equal(60, sdistFile.SizeBytes);
        Assert.Equal(accepted.Sha256, sdistFile.ChecksumSha256);
        Assert.Equal(160, version.SizeBytes);
        // The version row's PRIMARY artifact columns (the wheel's) were not clobbered by the
        // non-primary overwrite. (Scan-state reset on file change is pinned at the repository
        // level; here the synchronous post-publish rescan has already re-stamped it.)
        Assert.EndsWith("mfow-1.0.0-py3-none-any.whl", version.BlobKey);
    }

    [Fact]
    public async Task Pypi_QuotaAccountsPerFile_AddReservesFullSize_OverwriteReservesDelta()
    {
        await new OrgRepository(_db).SetStorageQuotaBytesAsync("o1", 220);
        await using (var conn = await _db.OpenAsync())
        {
            await conn.ExecuteAsync(
                "INSERT INTO org_settings (org_id, version_overwrite_policy, allow_version_overwrite) VALUES ('o1', 'allow', 1)");
        }

        var svc = Build();
        Assert.IsType<PublishResult.Accepted>(
            await svc.StoreAndRecordAsync(PypiSample("mfq", "1.0.0", "mfq-1.0.0-py3-none-any.whl", size: 100)));
        // Adding the sdist replaces nothing: it must reserve its FULL size. 100 + 130 > 220 → 413.
        var rej = Assert.IsType<PublishResult.Rejected>(
            await svc.StoreAndRecordAsync(PypiSample("mfq", "1.0.0", "mfq-1.0.0.tar.gz", size: 130)));
        Assert.Equal(413, rej.HttpStatus);
        Assert.Equal("tenant_quota_exceeded", rej.Code);

        // A smaller sdist fits (100 + 110 <= 220).
        Assert.IsType<PublishResult.Accepted>(
            await svc.StoreAndRecordAsync(PypiSample("mfq", "1.0.0", "mfq-1.0.0.tar.gz", size: 110)));

        // Overwriting the sdist reserves only the delta vs THAT file (not the version total):
        // 120 - 110 = +10 fits the remaining headroom exactly.
        Assert.IsType<PublishResult.Accepted>(
            await svc.StoreAndRecordAsync(PypiSample("mfq", "1.0.0", "mfq-1.0.0.tar.gz", size: 120)));
        // One more byte over the cap is rejected: 121 - 120 = +1 > 0 remaining.
        var overCap = Assert.IsType<PublishResult.Rejected>(
            await svc.StoreAndRecordAsync(PypiSample("mfq", "1.0.0", "mfq-1.0.0.tar.gz", size: 121)));
        Assert.Equal(413, overCap.HttpStatus);
    }

    [Fact]
    public async Task Pypi_FileRowInsertFailureOnNewVersion_ReleasesQuotaExactlyOnce()
    {
        // A failed file-row insert after the version row was created rolls the ROW back
        // without touching the tenant counter — the publish's own reservation release is
        // the single give-back. A counter-coupled rollback would decrement twice and drift
        // the counter low (the direction that lets a tenant exceed its real quota).
        await new OrgRepository(_db).SetStorageQuotaBytesAsync("o1", 10_000);
        var svc = Build();
        Assert.IsType<PublishResult.Accepted>(
            await svc.StoreAndRecordAsync(PypiSample("mfroll-base", "1.0.0", "mfroll_base-1.0.0-py3-none-any.whl", size: 500)));

        // Dropping package_version_files inside PutAsync makes CreateVersionAsync succeed
        // and the subsequent file-row insert throw — the exact rollback window under test.
        var droppingRegistry = new DropTableOnPutBlobStore(_blobs, _db, "package_version_files");
        var failing = BuildWithRegistry(droppingRegistry);
        await Assert.ThrowsAnyAsync<Exception>(() =>
            failing.StoreAndRecordAsync(PypiSample("mfroll", "1.0.0", "mfroll-1.0.0-py3-none-any.whl", size: 100)));

        await using var conn = await _db.OpenAsync();
        long used = await conn.ExecuteScalarAsync<long>(
            "SELECT storage_used_bytes FROM org_settings WHERE org_id = 'o1'");
        Assert.Equal(500, used);

        // The rolled-back version row is gone (no zero-file version survives).
        long orphanVersions = await conn.ExecuteScalarAsync<long>(
            """
            SELECT COUNT(*) FROM package_versions pv
            JOIN packages p ON p.id = pv.package_id
            WHERE p.org_id = 'o1' AND p.purl_name = 'mfroll'
            """);
        Assert.Equal(0, orphanVersions);
    }

    [Fact]
    public async Task Pypi_ConcurrentSameNewFilename_LoserDoesNotDeleteWinnersBlob()
    {
        // Two concurrent publishes of the SAME new filename to one version share a hosted
        // blob key. The loser's UNIQUE(version, filename) failure must NOT trigger the
        // fresh-blob compensating delete — that would 404 the winner's committed artifact.
        var svc = Build();
        var wheel = PypiSample("mfrace", "1.0.0", "mfrace-1.0.0-py3-none-any.whl");
        Assert.IsType<PublishResult.Accepted>(await svc.StoreAndRecordAsync(wheel));
        var packages = new PackageRepository(_db);
        var pkg = await packages.GetByPurlNameAsync("o1", "pypi", "mfrace");
        var version = await packages.GetVersionAsync(pkg!.Id, "1.0.0");

        // Simulate the race: the "winner's" file row lands during the loser's PutAsync —
        // after the loser's file-slot probe read the slot as absent, before its insert.
        var racingRegistry = new InsertFileRowOnPutBlobStore(_blobs, _db, version!.Id, "mfrace-1.0.0.tar.gz");
        var loser = BuildWithRegistry(racingRegistry);
        await Assert.ThrowsAnyAsync<Exception>(() =>
            loser.StoreAndRecordAsync(PypiSample("mfrace", "1.0.0", "mfrace-1.0.0.tar.gz", size: 40)));

        // The shared blob survives — the winner's committed file record still resolves.
        Assert.True(await _blobs.ExistsAsync(
            BlobKeys.Hosted("o1", "pypi", "mfrace", "1.0.0", "mfrace-1.0.0.tar.gz")),
            "the loser's compensation must not delete the blob the race winner's row references");
    }

    // Simulates the concurrent-publish race window for the same NEW filename: inserts the
    // winner's package_version_files row during PutAsync — after the loser's file-slot probe,
    // before its own insert — then delegates the blob write.
    private sealed class InsertFileRowOnPutBlobStore : IBlobStore
    {
        private readonly IBlobStore _inner;
        private readonly IMetadataStore _db;
        private readonly string _versionId;
        private readonly string _filename;
        public InsertFileRowOnPutBlobStore(IBlobStore inner, IMetadataStore db, string versionId, string filename)
        {
            _inner = inner;
            _db = db;
            _versionId = versionId;
            _filename = filename;
        }

        public async Task PutAsync(string key, Stream content, CancellationToken ct = default)
        {
            await using (var conn = await _db.OpenAsync(ct))
            {
                await conn.ExecuteAsync(
                    """
                    INSERT INTO package_version_files
                        (id, package_version_id, org_id, filename, blob_key, size_bytes, checksum_sha256, created_at)
                    VALUES (@id, @versionId, 'o1', @filename, @key, 40, 'winner-sha', '2024-01-01T00:00:00Z')
                    """,
                    new { id = Guid.NewGuid().ToString("N"), versionId = _versionId, filename = _filename, key });
            }
            await _inner.PutAsync(key, content, ct);
        }

        public Task<Stream?> GetAsync(string key, CancellationToken ct = default) => _inner.GetAsync(key, ct);
        public Task<RangedStream?> GetRangeAsync(string key, long offset, long length, CancellationToken ct = default)
            => _inner.GetRangeAsync(key, offset, length, ct);
        public Task<bool> ExistsAsync(string key, CancellationToken ct = default) => _inner.ExistsAsync(key, ct);
        public Task DeleteAsync(string key, CancellationToken ct = default) => _inner.DeleteAsync(key, ct);
        public Task<long> GetTotalSizeAsync(CancellationToken ct = default) => _inner.GetTotalSizeAsync(ct);
        public IAsyncEnumerable<BlobInfo> ListAsync(string prefix, CancellationToken ct = default)
            => _inner.ListAsync(prefix, ct);
    }
}
