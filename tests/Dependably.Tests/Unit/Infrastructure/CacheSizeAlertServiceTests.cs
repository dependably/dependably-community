using System.Data.Common;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Redis;
using Dependably.Infrastructure.SystemEvents;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using NSubstitute;

namespace Dependably.Tests.Unit.Infrastructure;

/// <summary>
/// <see cref="CacheSizeAlertService"/>: alerts once per upward crossing of
/// <c>instance_settings.cache_size_warn_bytes</c>, stays silent on a repeat pass over the same
/// state, re-arms on a drop back under the threshold, and is a no-op at 0/absent. The cache figure
/// is measured from the database (<c>CacheArtifactRepository.GetTotalSizeBytesAsync</c> +
/// <c>GetOciProxyOnlyDistinctDigestBytesAsync</c>) — never from
/// <c>dependably.blob_store.size_bytes{tier="cache"}</c>, which only exists when the cache and
/// registry tiers are split — so tests seed <c>cache_artifact</c>/<c>oci_blobs</c> rows directly.
/// </summary>
[Trait("Category", "Unit")]
public sealed class CacheSizeAlertServiceTests : IAsyncLifetime
{
    private static readonly DateTimeOffset Now = new(2026, 9, 27, 12, 0, 0, TimeSpan.Zero);

    private TestMetadataStore _db = null!;
    private OrgRepository _orgs = null!;
    private AuditRepository _audit = null!;
    private CacheArtifactRepository _cacheArtifacts = null!;
    private string _orgId = null!;

    private sealed class RecordingSystemEventNotifier : ISystemEventNotifier
    {
        public List<SystemEventRecord> Records { get; } = [];
        public void Notify(SystemEventRecord record) => Records.Add(record);
    }

    /// <summary>Minimal <see cref="IMetadataStore"/> that fails every open — simulates a DB the
    /// service cannot reach, isolated to whichever single repository it is handed to.</summary>
    private sealed class ThrowingMetadataStore : IMetadataStore
    {
        public DbProvider Provider => DbProvider.Sqlite;

        public Task<DbConnection> OpenAsync(CancellationToken ct = default) =>
            throw new InvalidOperationException("simulated database failure");
    }

    public async Task InitializeAsync()
    {
        _db = new TestMetadataStore();
        await new SchemaInitializer(_db).InitializeAsync();
        _orgs = new OrgRepository(_db);
        _audit = new AuditRepository(_db, null, TimeProvider.System);
        _cacheArtifacts = new CacheArtifactRepository(_db);
        _orgId = await OrgSeeder.InsertAsync(_db, $"cache-size-{Guid.NewGuid():N}"[..20]);
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    private CacheSizeAlertService Build(
        FakeTimeProvider clock,
        RecordingSystemEventNotifier notifier,
        IDistributedLock? locks = null,
        CacheArtifactRepository? cacheArtifacts = null,
        AuditRepository? audit = null)
    {
        var config = new ConfigurationBuilder().Build();
        var airGap = Substitute.For<IAirGapMode>();
        airGap.IsJobDisabled(Arg.Any<string>()).Returns(false);

        return new CacheSizeAlertService(
            _orgs,
            cacheArtifacts ?? _cacheArtifacts,
            audit ?? _audit,
            notifier,
            airGap,
            config,
            NullLogger<CacheSizeAlertService>.Instance,
            clock,
            locks ?? new InProcessDistributedLock(clock));
    }

    /// <summary>Replaces every <c>cache_artifact</c>/<c>oci_blobs</c> row with exactly the total
    /// <paramref name="bytes"/> the service should measure, split arbitrarily across one plain
    /// cache-artifact row and one proxy-only OCI digest so both halves of the sum are exercised.</summary>
    private async Task SetMeasuredCacheBytesAsync(long bytes)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync("DELETE FROM cache_artifact");
        await conn.ExecuteAsync("DELETE FROM oci_blobs");

        if (bytes <= 0)
        {
            return;
        }

        long ociShare = bytes / 2;
        long artifactShare = bytes - ociShare;

        if (artifactShare > 0)
        {
            await _cacheArtifacts.InsertAsync(new CacheArtifact
            {
                Id = Guid.NewGuid().ToString("N"),
                Ecosystem = "npm",
                Name = "pkg",
                Version = "1.0.0",
                Filename = "pkg-1.0.0.tgz",
                BlobKey = $"proxy/{Guid.NewGuid():N}",
                ContentHash = new string('a', 64),
                SizeBytes = artifactShare,
                FirstCachedAt = Now,
                LastAccessedAt = Now,
            });
        }

        if (ociShare > 0)
        {
            await conn.ExecuteAsync(
                """
                INSERT INTO oci_blobs (digest, org_id, media_type, size_bytes, blob_key, origin)
                VALUES (@digest, @orgId, 'application/vnd.oci.image.layer.v1.tar+gzip', @sizeBytes, @blobKey, 'proxy')
                """,
                new
                {
                    digest = $"sha256:{Guid.NewGuid():N}",
                    orgId = _orgId,
                    sizeBytes = ociShare,
                    blobKey = $"oci/sha256/{Guid.NewGuid():N}",
                });
        }
    }

    private async Task<(IReadOnlyList<AuditEntry> Items, int Total)> ListAuditAsync()
        => await _audit.ListSystemAuditAsync(50, 0, action: "system.cache_size_threshold_exceeded");

    private async Task<string?> ReadSettingAsync(string key) => await _orgs.GetInstanceSettingAsync(key);

    // ── Crossing fires once ──────────────────────────────────────────────────────

    [Fact]
    public async Task UpwardCrossing_EmitsAuditRowAndSlackNotification()
    {
        var clock = TestTime.Frozen(Now);
        await _orgs.SetInstanceSettingAsync(CacheSizeAlertService.WarnBytesSettingKey, "1000");
        await SetMeasuredCacheBytesAsync(1500);
        var notifier = new RecordingSystemEventNotifier();

        await Build(clock, notifier).RunCheckPassAsync(CancellationToken.None);

        var (items, total) = await ListAuditAsync();
        Assert.Equal(1, total);
        Assert.Contains("1500", items[0].Detail!);
        Assert.Contains("1000", items[0].Detail!);

        var record = Assert.Single(notifier.Records);
        Assert.Equal("system.cache_size_threshold_exceeded", record.Action);
        Assert.Null(record.Actor);
        Assert.Null(record.TenantSlug);

        Assert.Equal("1", await ReadSettingAsync(CacheSizeAlertService.CrossedStateSettingKey));
        Assert.Equal("1500", await ReadSettingAsync(CacheSizeAlertService.LastBytesSettingKey));
        Assert.NotNull(await ReadSettingAsync(CacheSizeAlertService.LastMeasuredAtSettingKey));
    }

    [Fact]
    public async Task RepeatPassStillOverThreshold_StaysSilent()
    {
        var clock = TestTime.Frozen(Now);
        await _orgs.SetInstanceSettingAsync(CacheSizeAlertService.WarnBytesSettingKey, "1000");
        await SetMeasuredCacheBytesAsync(1500);
        var notifier = new RecordingSystemEventNotifier();
        var svc = Build(clock, notifier);

        await svc.RunCheckPassAsync(CancellationToken.None);
        await svc.RunCheckPassAsync(CancellationToken.None);
        await svc.RunCheckPassAsync(CancellationToken.None);

        var (_, total) = await ListAuditAsync();
        Assert.Equal(1, total);
        Assert.Single(notifier.Records);
    }

    [Fact]
    public async Task DroppingBelowThreshold_RearmsForTheNextCrossing()
    {
        var clock = TestTime.Frozen(Now);
        await _orgs.SetInstanceSettingAsync(CacheSizeAlertService.WarnBytesSettingKey, "1000");
        var notifier = new RecordingSystemEventNotifier();
        var svc = Build(clock, notifier);

        await SetMeasuredCacheBytesAsync(1500);
        await svc.RunCheckPassAsync(CancellationToken.None);
        Assert.Single(notifier.Records);

        // Drops back under threshold: re-arms, no new alert for the drop itself.
        await SetMeasuredCacheBytesAsync(500);
        await svc.RunCheckPassAsync(CancellationToken.None);
        Assert.Single(notifier.Records);
        Assert.Equal("0", await ReadSettingAsync(CacheSizeAlertService.CrossedStateSettingKey));

        // Crosses again: a second, independent alert.
        await SetMeasuredCacheBytesAsync(1600);
        await svc.RunCheckPassAsync(CancellationToken.None);
        Assert.Equal(2, notifier.Records.Count);

        var (_, total) = await ListAuditAsync();
        Assert.Equal(2, total);
    }

    // ── Disabled at 0/absent ─────────────────────────────────────────────────────

    [Fact]
    public async Task ThresholdExplicitlyZero_NeverAlerts_RegardlessOfCacheSize()
    {
        var clock = TestTime.Frozen(Now);
        await _orgs.SetInstanceSettingAsync(CacheSizeAlertService.WarnBytesSettingKey, "0");
        await SetMeasuredCacheBytesAsync(1_000_000_000);
        var notifier = new RecordingSystemEventNotifier();

        await Build(clock, notifier).RunCheckPassAsync(CancellationToken.None);

        Assert.Empty(notifier.Records);
        var (_, total) = await ListAuditAsync();
        Assert.Equal(0, total);
    }

    [Fact]
    public async Task ThresholdAbsent_FallsBackToDefault_StillAlertsPastIt()
    {
        // Absent (never configured) is NOT the same as an explicit zero — it falls back to
        // InstanceSettingDefaults.CacheSizeWarnBytes, which is enabled by default.
        var clock = TestTime.Frozen(Now);
        await SetMeasuredCacheBytesAsync(long.Parse(InstanceSettingDefaults.CacheSizeWarnBytes) + 1);
        var notifier = new RecordingSystemEventNotifier();

        await Build(clock, notifier).RunCheckPassAsync(CancellationToken.None);

        Assert.Single(notifier.Records);
    }

    [Fact]
    public async Task DisabledViaAirGap_SkipsEntirely()
    {
        var clock = TestTime.Frozen(Now);
        await _orgs.SetInstanceSettingAsync(CacheSizeAlertService.WarnBytesSettingKey, "1000");
        await SetMeasuredCacheBytesAsync(5000);
        var notifier = new RecordingSystemEventNotifier();
        var config = new ConfigurationBuilder().Build();
        var airGap = Substitute.For<IAirGapMode>();
        airGap.IsJobDisabled(CacheSizeAlertService.JobName).Returns(true);

        var svc = new CacheSizeAlertService(
            _orgs, _cacheArtifacts, _audit, notifier, airGap, config,
            NullLogger<CacheSizeAlertService>.Instance, clock, new InProcessDistributedLock(clock));

        await svc.RunCheckPassAsync(CancellationToken.None);

        Assert.Empty(notifier.Records);
    }

    // ── Measurement unavailable must never read as zero ─────────────────────────

    [Fact]
    public async Task MeasurementThrows_WhileAlreadyCrossed_FlagStaysCrossed_NoSecondAlert()
    {
        var clock = TestTime.Frozen(Now);
        await _orgs.SetInstanceSettingAsync(CacheSizeAlertService.WarnBytesSettingKey, "1000");
        var notifier = new RecordingSystemEventNotifier();

        // First tick: real measurement, crosses and alerts.
        await SetMeasuredCacheBytesAsync(1500);
        await Build(clock, notifier).RunCheckPassAsync(CancellationToken.None);
        Assert.Single(notifier.Records);
        Assert.Equal("1", await ReadSettingAsync(CacheSizeAlertService.CrossedStateSettingKey));

        // Second tick: the cache repository is unreachable. A failed measurement must never be
        // treated as zero (which would falsely re-arm), so the flag must stay "1" and no second
        // alert (nor a silent re-arm) must occur.
        var brokenArtifacts = new CacheArtifactRepository(new ThrowingMetadataStore());
        var svc = Build(clock, notifier, cacheArtifacts: brokenArtifacts);
        await svc.RunCheckPassAsync(CancellationToken.None);

        Assert.Single(notifier.Records); // unchanged
        Assert.Equal("1", await ReadSettingAsync(CacheSizeAlertService.CrossedStateSettingKey));
        var (_, total) = await ListAuditAsync();
        Assert.Equal(1, total);
    }

    [Fact]
    public async Task MeasurementThrows_NoPriorState_SkipsWithNoStateWrittenAtAll()
    {
        var clock = TestTime.Frozen(Now);
        await _orgs.SetInstanceSettingAsync(CacheSizeAlertService.WarnBytesSettingKey, "1000");
        var notifier = new RecordingSystemEventNotifier();
        var brokenArtifacts = new CacheArtifactRepository(new ThrowingMetadataStore());

        await Build(clock, notifier, cacheArtifacts: brokenArtifacts).RunCheckPassAsync(CancellationToken.None);

        Assert.Empty(notifier.Records);
        Assert.Null(await ReadSettingAsync(CacheSizeAlertService.CrossedStateSettingKey));
        Assert.Null(await ReadSettingAsync(CacheSizeAlertService.LastBytesSettingKey));
        Assert.Null(await ReadSettingAsync(CacheSizeAlertService.LastMeasuredAtSettingKey));
    }

    // ── Crossed flag persists only after audit + notify succeed ─────────────────

    [Fact]
    public async Task AuditWriteThrows_FlagStaysUnset_NextTickAlerts()
    {
        var clock = TestTime.Frozen(Now);
        await _orgs.SetInstanceSettingAsync(CacheSizeAlertService.WarnBytesSettingKey, "1000");
        await SetMeasuredCacheBytesAsync(1500);
        var notifier = new RecordingSystemEventNotifier();
        var brokenAudit = new AuditRepository(new ThrowingMetadataStore(), null, TimeProvider.System);

        var svc = Build(clock, notifier, audit: brokenAudit);
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => svc.RunCheckPassAsync(CancellationToken.None));

        // The audit write threw before Notify and before the flag was persisted — none of it
        // happened, so a retry must be a genuine first attempt, not a no-op.
        Assert.Empty(notifier.Records);
        Assert.Null(await ReadSettingAsync(CacheSizeAlertService.CrossedStateSettingKey));

        // The next tick, with a working audit repository, alerts exactly as if the first attempt
        // had never happened.
        var retrySvc = Build(clock, notifier);
        await retrySvc.RunCheckPassAsync(CancellationToken.None);

        Assert.Single(notifier.Records);
        Assert.Equal("1", await ReadSettingAsync(CacheSizeAlertService.CrossedStateSettingKey));
        var (_, total) = await ListAuditAsync();
        Assert.Equal(1, total);
    }

    // ── Leader lock respected ────────────────────────────────────────────────────

    // ScheduledBackgroundService's leader-lock gating lives in the private RunTickGuardedAsync —
    // the method the cron loop actually calls each occurrence. Driving it directly via reflection
    // pins the real gating path without racing a FakeTimeProvider against the hourly cron
    // schedule (ScheduledBackgroundServiceLeaseTests already covers the lease-renewal mechanics
    // generically; this test pins that CacheSizeAlertService is wired into it).
    private static Task InvokeGuardedTickAsync(CacheSizeAlertService svc, CancellationToken ct)
    {
        var method = typeof(ScheduledBackgroundService).GetMethod(
            "RunTickGuardedAsync", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)
            ?? throw new InvalidOperationException("RunTickGuardedAsync not found — base class shape changed.");
        return (Task)method.Invoke(svc, [ct])!;
    }

    [Fact]
    public async Task AnotherReplicaHoldingTheLeaderLock_TickIsSkipped()
    {
        var clock = TestTime.Frozen(Now);
        var locks = new InProcessDistributedLock(clock);
        var svc = Build(clock, new RecordingSystemEventNotifier(), locks);

        await using var held = await locks.TryAcquireAsync(
            $"job:{nameof(CacheSizeAlertService)}", TimeSpan.FromMinutes(5), CancellationToken.None);
        Assert.NotNull(held);

        await _orgs.SetInstanceSettingAsync(CacheSizeAlertService.WarnBytesSettingKey, "1000");
        await SetMeasuredCacheBytesAsync(5000);

        await InvokeGuardedTickAsync(svc, CancellationToken.None);

        var (_, total) = await ListAuditAsync();
        Assert.Equal(0, total);
    }

    [Fact]
    public async Task LockNotHeldByAnyoneElse_TickRunsNormally()
    {
        // The positive control for the test above: the same guarded-tick entry point, with no
        // competing holder, must let the pass run and alert.
        var clock = TestTime.Frozen(Now);
        var locks = new InProcessDistributedLock(clock);
        var svc = Build(clock, new RecordingSystemEventNotifier(), locks);

        await _orgs.SetInstanceSettingAsync(CacheSizeAlertService.WarnBytesSettingKey, "1000");
        await SetMeasuredCacheBytesAsync(5000);

        await InvokeGuardedTickAsync(svc, CancellationToken.None);

        var (_, total) = await ListAuditAsync();
        Assert.Equal(1, total);
    }
}
