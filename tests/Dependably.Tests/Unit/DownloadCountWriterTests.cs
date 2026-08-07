using System.Diagnostics.Metrics;
using Dapper;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Observability;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit;

/// <summary>
/// Acceptance tests for <see cref="PackageRepository.IncrementDownloadCountAsync"/> and
/// <see cref="TenantArtifactAccessRepository.RecordDownloadHitAsync"/> off-path behaviour:
/// when a <see cref="DownloadCountWriter"/> is wired in, the hot path must enqueue without
/// touching the DB; the hosted-service drainer must aggregate and flush the counts.
/// The cache-plane path increments <c>tenant_artifact_access.download_count</c> scoped to the
/// caller's org_id (proxy download counts live in the global plane, not in package_versions),
/// keyed by cache_artifact id so a download is never counted against a sibling file.
/// </summary>
// Attaches a MeterListener filtered only by DependablyMeter.MeterName + instrument name and
// asserts exact counts — must run alone against the process-wide static meter.
// See MeterSensitiveCollection.
[Trait("Category", "Unit")]
[Collection("MeterSensitive")]
public sealed class DownloadCountWriterTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private string _orgId = default!;
    private string _versionId = default!;
    private string _purl = default!;
    private string _cacheArtifactId = default!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();

        _orgId = $"org-{Guid.NewGuid():N}";
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES (@id, @slug)",
            new { id = _orgId, slug = _orgId });

        string pkgId = $"pkg-{Guid.NewGuid():N}";
        _purl = "pkg:npm/lib@1.0.0";
        await conn.ExecuteAsync(
            "INSERT INTO packages (id, org_id, ecosystem, name, purl_name) VALUES (@pkgId, @orgId, 'npm', 'lib', 'lib')",
            new { pkgId, orgId = _orgId });

        _versionId = $"ver-{Guid.NewGuid():N}";
        await conn.ExecuteAsync(
            """
            INSERT INTO package_versions
                (id, package_id, version, purl, blob_key, size_bytes, checksum_sha256, origin)
            VALUES
                (@id, @pkgId, '1.0.0', @purl, 'registry/npm/lib/1.0.0/lib-1.0.0.tgz',
                 1000, 'aaaa', 'uploaded')
            """,
            new { id = _versionId, pkgId, purl = _purl });

        // Seed a cache_artifact + tenant_artifact_access row for the by-purl path.
        _cacheArtifactId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            """
            INSERT INTO cache_artifact
                (id, ecosystem, name, version, filename, blob_key, content_hash, purl)
            VALUES
                (@id, 'npm', 'lib', '1.0.0', 'lib-1.0.0.tgz',
                 'proxy/aaaa/lib-1.0.0.tgz', 'aaaa', @purl)
            """,
            new { id = _cacheArtifactId, purl = _purl });

        await conn.ExecuteAsync(
            """
            INSERT INTO tenant_artifact_access
                (org_id, cache_artifact_id, download_count)
            VALUES (@orgId, @caId, 0)
            """,
            new { orgId = _orgId, caId = _cacheArtifactId });
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    /// <summary>
    /// Seeds a second cache_artifact row carrying the SAME purl as <c>_cacheArtifactId</c> under a
    /// different filename — the Maven/RPM shape, where one purl spans a version's several files.
    /// Returns its id so a test can assert it was left alone.
    /// </summary>
    private async Task<string> SeedSiblingCacheArtifactSharingPurlAsync()
    {
        await using var conn = await _db.OpenAsync();
        string siblingId = Guid.NewGuid().ToString("N");
        await conn.ExecuteAsync(
            """
            INSERT INTO cache_artifact
                (id, ecosystem, name, version, filename, blob_key, content_hash, purl)
            VALUES
                (@id, 'npm', 'lib', '1.0.0', 'lib-1.0.0.tgz.sig',
                 'proxy/bbbb/lib-1.0.0.tgz.sig', 'bbbb', @purl)
            """,
            new { id = siblingId, purl = _purl });

        await conn.ExecuteAsync(
            """
            INSERT INTO tenant_artifact_access
                (org_id, cache_artifact_id, download_count)
            VALUES (@orgId, @caId, 0)
            """,
            new { orgId = _orgId, caId = siblingId });

        return siblingId;
    }

    // ── Capacity defaults ────────────────────────────────────────────────────

    [Fact]
    public void DefaultCapacity_Is_50k()
    {
        Assert.Equal(50_000, DownloadCountWriter.DefaultChannelCapacity);
    }

    [Fact]
    public void ChannelCapacity_UsesDefault_WhenNullPassed()
    {
        var writer = new DownloadCountWriter();
        Assert.Equal(DownloadCountWriter.DefaultChannelCapacity, writer.ChannelCapacity);
    }

    [Fact]
    public void ChannelCapacity_Configurable_WithCustomValue()
    {
        var writer = new DownloadCountWriter(capacity: 9);
        Assert.Equal(9, writer.ChannelCapacity);
    }

    [Fact]
    public void ChannelCapacity_IgnoresNonPositive_FallsBackToDefault()
    {
        var writer = new DownloadCountWriter(capacity: 0);
        Assert.Equal(DownloadCountWriter.DefaultChannelCapacity, writer.ChannelCapacity);
    }

    // ── TryEnqueue ───────────────────────────────────────────────────────────

    [Fact]
    public void TryEnqueue_BelowCapacity_Returns_True()
    {
        var writer = new DownloadCountWriter();
        Assert.True(writer.TryEnqueue(new DownloadCountRecord(VersionId: "v1")));
    }

    [Fact]
    public void TryEnqueue_AtCustomCapacity_DropsRecord_ReturnsFalse()
    {
        const int cap = 5;
        var writer = new DownloadCountWriter(capacity: cap);
        for (int i = 0; i < cap; i++)
        {
            Assert.True(writer.TryEnqueue(new DownloadCountRecord(VersionId: $"v{i}")));
        }
        Assert.False(writer.TryEnqueue(new DownloadCountRecord(VersionId: "overflow")));
    }

    // ── Drop-meter fires on full channel ────────────────────────────────────

    [Fact]
    public void TryEnqueue_OverCapacity_IncrementsDropMeter()
    {
        const int cap = 3;
        var writer = new DownloadCountWriter(capacity: cap);

        long drops = 0;
        using var listener = DropMeterListener(delta => drops += delta);

        for (int i = 0; i < cap; i++)
        {
            writer.TryEnqueue(new DownloadCountRecord(VersionId: $"v{i}"));
        }

        bool enqueued = writer.TryEnqueue(new DownloadCountRecord(VersionId: "overflow"));

        Assert.False(enqueued);
        Assert.Equal(1, drops);
    }

    // ── Mixed partial-failure scenario (house rule) ──────────────────────────
    // A burst that partially exceeds capacity: under-capacity writes succeed and persist
    // after drain; only overflow records are dropped and counted.

    [Fact]
    public async Task MixedBurst_PartiallyExceedsCapacity_OnlyOverflowDropped()
    {
        // Mixed burst: alternates versionId records (→ package_versions) and orgId+purl records
        // (→ tenant_artifact_access). Both write to the correct target plane. Overflow records
        // are dropped; only up to cap records reach the DB.
        const int cap = 4;
        const int burst = 7;
        const int expectedDrops = burst - cap;

        var writer = new DownloadCountWriter(capacity: cap);
        var service = new DownloadCountWriterHostedService(writer, _db,
            NullLogger<DownloadCountWriterHostedService>.Instance,
            TimeProvider.System);

        long drops = 0;
        using var listener = DropMeterListener(delta => drops += delta);

        int successCount = 0;
        for (int i = 0; i < burst; i++)
        {
            // Alternate between versionId (uploaded plane) and orgId+purl (global plane) strategies.
            var record = i % 2 == 0
                ? new DownloadCountRecord(VersionId: _versionId)
                : new DownloadCountRecord(VersionId: null, OrgId: _orgId, CacheArtifactId: _cacheArtifactId);
            if (writer.TryEnqueue(record))
            {
                successCount++;
            }
        }

        Assert.Equal(cap, successCount);
        Assert.Equal(expectedDrops, drops);

        // Drain: versionId records land in package_versions; purl records in tenant_artifact_access.
        await service.DrainPendingAsync();

        await using var conn = await _db.OpenAsync();

        // package_versions gets the even-index versionId records (indices 0, 2 → 2 records fit within cap=4).
        int pvCount = await conn.ExecuteScalarAsync<int>(
            "SELECT download_count FROM package_versions WHERE id = @id",
            new { id = _versionId });

        // tenant_artifact_access gets the odd-index purl records (indices 1, 3 → 2 records fit within cap=4).
        int taaCount = await conn.ExecuteScalarAsync<int>(
            "SELECT download_count FROM tenant_artifact_access WHERE org_id = @orgId AND cache_artifact_id = @caId",
            new { orgId = _orgId, caId = _cacheArtifactId });

        // Total across both planes equals the number of successfully queued records.
        Assert.Equal(cap, pvCount + taaCount);
    }

    // ── IncrementDownloadCountAsync — off-path enqueue ───────────────────────

    [Fact]
    public async Task IncrementDownloadCountAsync_WithWriter_DoesNotWriteSynchronously()
    {
        var writer = new DownloadCountWriter();
        var repo = new PackageRepository(_db, writer);

        await repo.IncrementDownloadCountAsync(_versionId);

        await using var conn = await _db.OpenAsync();
        int count = await conn.ExecuteScalarAsync<int>(
            "SELECT download_count FROM package_versions WHERE id = @id",
            new { id = _versionId });
        Assert.Equal(0, count);
    }

    [Fact]
    public async Task IncrementDownloadCountAsync_WithoutWriter_WritesSynchronously()
    {
        var repo = new PackageRepository(_db);

        await repo.IncrementDownloadCountAsync(_versionId);

        await using var conn = await _db.OpenAsync();
        int count = await conn.ExecuteScalarAsync<int>(
            "SELECT download_count FROM package_versions WHERE id = @id",
            new { id = _versionId });
        Assert.Equal(1, count);
    }

    // ── RecordDownloadHitAsync — off-path enqueue ────────────────────────────
    // Cache-plane increments target tenant_artifact_access.download_count keyed by the
    // cache_artifact id, not package_versions — proxy download counts are per-tenant on the
    // global plane. Keying by row id rather than purl is load-bearing: a purl is not unique on
    // that plane (Maven/RPM map one purl to several filenames), so a purl-keyed bump would
    // count one file's download against all of its siblings.

    [Fact]
    public async Task RecordDownloadHitAsync_WithWriter_DoesNotWriteSynchronously()
    {
        var writer = new DownloadCountWriter();
        var access = new TenantArtifactAccessRepository(_db, writer);

        await access.RecordDownloadHitAsync(_orgId, _cacheArtifactId, TestTime.Frozen().GetUtcNow());

        await using var conn = await _db.OpenAsync();
        int count = await conn.ExecuteScalarAsync<int>(
            "SELECT download_count FROM tenant_artifact_access WHERE org_id = @orgId AND cache_artifact_id = @caId",
            new { orgId = _orgId, caId = _cacheArtifactId });
        Assert.Equal(0, count); // not yet flushed
    }

    [Fact]
    public async Task RecordDownloadHitAsync_WithoutWriter_WritesSynchronously()
    {
        var access = new TenantArtifactAccessRepository(_db);

        await access.RecordDownloadHitAsync(_orgId, _cacheArtifactId, TestTime.Frozen().GetUtcNow());

        await using var conn = await _db.OpenAsync();
        int count = await conn.ExecuteScalarAsync<int>(
            "SELECT download_count FROM tenant_artifact_access WHERE org_id = @orgId AND cache_artifact_id = @caId",
            new { orgId = _orgId, caId = _cacheArtifactId });
        Assert.Equal(1, count);
    }

    // ── Mixed partial-failure scenario, both key strategies ──────────────────
    // A burst rotating through both DownloadCountRecord shapes (versionId, orgId+cacheArtifactId)
    // that partially exceeds capacity: under-capacity writes persist after drain, split correctly
    // across their target planes; only overflow is dropped.

    [Fact]
    public async Task MixedBurst_BothKeyStrategies_PartiallyExceedsCapacity_OnlyOverflowDropped()
    {
        const int cap = 6;
        const int burst = 9;
        const int expectedDrops = burst - cap;

        var writer = new DownloadCountWriter(capacity: cap);
        var service = new DownloadCountWriterHostedService(writer, _db,
            NullLogger<DownloadCountWriterHostedService>.Instance,
            TimeProvider.System);

        long drops = 0;
        using var listener = DropMeterListener(delta => drops += delta);

        int successCount = 0;
        for (int i = 0; i < burst; i++)
        {
            var record = i % 2 == 0
                ? new DownloadCountRecord(VersionId: _versionId)
                : new DownloadCountRecord(VersionId: null, OrgId: _orgId, CacheArtifactId: _cacheArtifactId);
            if (writer.TryEnqueue(record))
            {
                successCount++;
            }
        }

        Assert.Equal(cap, successCount);
        Assert.Equal(expectedDrops, drops);

        await service.DrainPendingAsync();

        await using var conn = await _db.OpenAsync();
        int pvCount = await conn.ExecuteScalarAsync<int>(
            "SELECT download_count FROM package_versions WHERE id = @id", new { id = _versionId });
        int taaCount = await conn.ExecuteScalarAsync<int>(
            "SELECT download_count FROM tenant_artifact_access WHERE org_id = @orgId AND cache_artifact_id = @caId",
            new { orgId = _orgId, caId = _cacheArtifactId });

        Assert.Equal(cap, pvCount + taaCount);
    }

    // ── DrainPendingAsync — aggregation and flush ─────────────────────────────

    [Fact]
    public async Task DrainPendingAsync_ByVersionId_AggregatesMultipleIncrementsIntoSingleUpdate()
    {
        var writer = new DownloadCountWriter();
        var repo = new PackageRepository(_db, writer);
        var service = new DownloadCountWriterHostedService(writer, _db,
            NullLogger<DownloadCountWriterHostedService>.Instance,
            TimeProvider.System);

        // Enqueue 5 increments for the same version — all arrive in the same drain batch.
        for (int i = 0; i < 5; i++)
        {
            await repo.IncrementDownloadCountAsync(_versionId);
        }

        await service.DrainPendingAsync();

        await using var conn = await _db.OpenAsync();
        int count = await conn.ExecuteScalarAsync<int>(
            "SELECT download_count FROM package_versions WHERE id = @id",
            new { id = _versionId });
        Assert.Equal(5, count);
    }

    [Fact]
    public async Task DrainPendingAsync_ByCacheArtifactId_ViaRepository_AggregatesIntoSingleUpdate()
    {
        var writer = new DownloadCountWriter();
        var access = new TenantArtifactAccessRepository(_db, writer);
        var service = new DownloadCountWriterHostedService(writer, _db,
            NullLogger<DownloadCountWriterHostedService>.Instance,
            TimeProvider.System);

        var at = TestTime.Frozen().GetUtcNow();
        for (int i = 0; i < 3; i++)
        {
            await access.RecordDownloadHitAsync(_orgId, _cacheArtifactId, at);
        }

        await service.DrainPendingAsync();

        await using var conn = await _db.OpenAsync();
        // Cache-plane increments land in tenant_artifact_access.download_count (global plane).
        int count = await conn.ExecuteScalarAsync<int>(
            "SELECT download_count FROM tenant_artifact_access WHERE org_id = @orgId AND cache_artifact_id = @caId",
            new { orgId = _orgId, caId = _cacheArtifactId });
        Assert.Equal(3, count);
    }

    [Fact]
    public async Task DrainPendingAsync_SiblingCacheArtifactSharingAPurl_IsNotBumped()
    {
        // A purl is not unique on the cache plane: Maven and RPM map one purl to several
        // filenames. Keying the counter by cache_artifact id is what keeps one file's download
        // from being counted against its siblings — and from refreshing their last_used, which
        // would also perturb LRU eviction order.
        string siblingId = await SeedSiblingCacheArtifactSharingPurlAsync();

        var writer = new DownloadCountWriter();
        var access = new TenantArtifactAccessRepository(_db, writer);
        var service = new DownloadCountWriterHostedService(writer, _db,
            NullLogger<DownloadCountWriterHostedService>.Instance,
            TimeProvider.System);

        await access.RecordDownloadHitAsync(_orgId, _cacheArtifactId, TestTime.Frozen().GetUtcNow());
        await service.DrainPendingAsync();

        await using var conn = await _db.OpenAsync();
        int served = await conn.ExecuteScalarAsync<int>(
            "SELECT download_count FROM tenant_artifact_access WHERE org_id = @orgId AND cache_artifact_id = @caId",
            new { orgId = _orgId, caId = _cacheArtifactId });
        int sibling = await conn.ExecuteScalarAsync<int>(
            "SELECT download_count FROM tenant_artifact_access WHERE org_id = @orgId AND cache_artifact_id = @caId",
            new { orgId = _orgId, caId = siblingId });

        Assert.Equal(1, served);
        Assert.Equal(0, sibling);
    }

    [Fact]
    public async Task DrainPendingAsync_ByCacheArtifactId_AggregatesMultipleIncrementsIntoSingleUpdate()
    {
        // Every cache-plane serve path enqueues by (orgId, cacheArtifactId) — the row identity the
        // caller already holds, which is also what keeps a download off its sibling files.
        var writer = new DownloadCountWriter();
        var service = new DownloadCountWriterHostedService(writer, _db,
            NullLogger<DownloadCountWriterHostedService>.Instance,
            TimeProvider.System);

        for (int i = 0; i < 3; i++)
        {
            writer.TryEnqueue(new DownloadCountRecord(
                VersionId: null, OrgId: _orgId, CacheArtifactId: _cacheArtifactId));
        }

        await service.DrainPendingAsync();

        await using var conn = await _db.OpenAsync();
        int count = await conn.ExecuteScalarAsync<int>(
            "SELECT download_count FROM tenant_artifact_access WHERE org_id = @orgId AND cache_artifact_id = @caId",
            new { orgId = _orgId, caId = _cacheArtifactId });
        Assert.Equal(3, count);
    }

    [Fact]
    public async Task DrainPendingAsync_OverMaxBatch_FlushesAllRecords()
    {
        // 250 records > MaxBatch(200) — drainer must not drop or block; it keeps flushing.
        var writer = new DownloadCountWriter();
        var repo = new PackageRepository(_db, writer);
        var service = new DownloadCountWriterHostedService(writer, _db,
            NullLogger<DownloadCountWriterHostedService>.Instance,
            TimeProvider.System);

        for (int i = 0; i < 250; i++)
        {
            await repo.IncrementDownloadCountAsync(_versionId);
        }

        await service.DrainPendingAsync();

        await using var conn = await _db.OpenAsync();
        int count = await conn.ExecuteScalarAsync<int>(
            "SELECT download_count FROM package_versions WHERE id = @id",
            new { id = _versionId });
        Assert.Equal(250, count);
    }

    [Fact]
    public async Task DrainPendingAsync_MixedKeys_UpdatesBothPlanesIndependently()
    {
        var writer = new DownloadCountWriter();
        var repo = new PackageRepository(_db, writer);
        var access = new TenantArtifactAccessRepository(_db, writer);
        var service = new DownloadCountWriterHostedService(writer, _db,
            NullLogger<DownloadCountWriterHostedService>.Instance,
            TimeProvider.System);

        // Two uploaded-plane increments by versionId.
        await repo.IncrementDownloadCountAsync(_versionId);
        await repo.IncrementDownloadCountAsync(_versionId);
        // One global-plane increment by orgId+cacheArtifactId.
        await access.RecordDownloadHitAsync(_orgId, _cacheArtifactId, TestTime.Frozen().GetUtcNow());

        await service.DrainPendingAsync();

        await using var conn = await _db.OpenAsync();
        // Uploaded plane: package_versions gets the 2 versionId increments.
        int pvCount = await conn.ExecuteScalarAsync<int>(
            "SELECT download_count FROM package_versions WHERE id = @id",
            new { id = _versionId });
        Assert.Equal(2, pvCount);

        // Global plane: tenant_artifact_access gets the 1 cache-plane increment.
        int taaCount = await conn.ExecuteScalarAsync<int>(
            "SELECT download_count FROM tenant_artifact_access WHERE org_id = @orgId AND cache_artifact_id = @caId",
            new { orgId = _orgId, caId = _cacheArtifactId });
        Assert.Equal(1, taaCount);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Returns an active <see cref="MeterListener"/> that invokes <paramref name="onDrop"/>
    /// with each measurement delta emitted by
    /// <c>dependably.download_count_writer.dropped</c>. Must be disposed after the assertion.
    /// </summary>
    private static MeterListener DropMeterListener(Action<long> onDrop)
    {
        var listener = new MeterListener
        {
            InstrumentPublished = (instrument, l) =>
            {
                if (instrument.Meter.Name == DependablyMeter.MeterName &&
                    instrument.Name == "dependably.download_count_writer.dropped")
                {
                    l.EnableMeasurementEvents(instrument);
                }
            }
        };
        listener.SetMeasurementEventCallback<long>((_, measurement, _, _) => onDrop(measurement));
        listener.Start();
        return listener;
    }
}
