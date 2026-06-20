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
/// <see cref="PackageRepository.IncrementDownloadCountByPurlAsync"/> off-path behaviour:
/// when a <see cref="DownloadCountWriter"/> is wired in, the hot path must enqueue without
/// touching the DB; the hosted-service drainer must aggregate and flush the counts.
/// The by-purl path increments <c>tenant_artifact_access.download_count</c> scoped to the
/// caller's org_id (proxy download counts live in the global plane, not in package_versions).
/// </summary>
[Trait("Category", "Unit")]
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
        Assert.True(writer.TryEnqueue(new DownloadCountRecord(VersionId: "v1", Purl: null)));
    }

    [Fact]
    public void TryEnqueue_AtCustomCapacity_DropsRecord_ReturnsFalse()
    {
        const int cap = 5;
        var writer = new DownloadCountWriter(capacity: cap);
        for (int i = 0; i < cap; i++)
        {
            Assert.True(writer.TryEnqueue(new DownloadCountRecord(VersionId: $"v{i}", Purl: null)));
        }
        Assert.False(writer.TryEnqueue(new DownloadCountRecord(VersionId: "overflow", Purl: null)));
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
            writer.TryEnqueue(new DownloadCountRecord(VersionId: $"v{i}", Purl: null));
        }

        bool enqueued = writer.TryEnqueue(new DownloadCountRecord(VersionId: "overflow", Purl: null));

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
                ? new DownloadCountRecord(VersionId: _versionId, Purl: null)
                : new DownloadCountRecord(VersionId: null, Purl: _purl, OrgId: _orgId);
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

    // ── IncrementDownloadCountByPurlAsync — off-path enqueue ─────────────────
    // By-purl increments target tenant_artifact_access.download_count (global plane),
    // not package_versions — proxy download counts are now per-tenant in the global plane.

    [Fact]
    public async Task IncrementDownloadCountByPurlAsync_WithWriter_DoesNotWriteSynchronously()
    {
        var writer = new DownloadCountWriter();
        var repo = new PackageRepository(_db, writer);

        await repo.IncrementDownloadCountByPurlAsync(_orgId, _purl);

        await using var conn = await _db.OpenAsync();
        int count = await conn.ExecuteScalarAsync<int>(
            "SELECT download_count FROM tenant_artifact_access WHERE org_id = @orgId AND cache_artifact_id = @caId",
            new { orgId = _orgId, caId = _cacheArtifactId });
        Assert.Equal(0, count); // not yet flushed
    }

    [Fact]
    public async Task IncrementDownloadCountByPurlAsync_WithoutWriter_WritesSynchronously()
    {
        var repo = new PackageRepository(_db);

        await repo.IncrementDownloadCountByPurlAsync(_orgId, _purl);

        await using var conn = await _db.OpenAsync();
        int count = await conn.ExecuteScalarAsync<int>(
            "SELECT download_count FROM tenant_artifact_access WHERE org_id = @orgId AND cache_artifact_id = @caId",
            new { orgId = _orgId, caId = _cacheArtifactId });
        Assert.Equal(1, count);
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
    public async Task DrainPendingAsync_ByPurl_AggregatesMultipleIncrementsIntoSingleUpdate()
    {
        var writer = new DownloadCountWriter();
        var repo = new PackageRepository(_db, writer);
        var service = new DownloadCountWriterHostedService(writer, _db,
            NullLogger<DownloadCountWriterHostedService>.Instance,
            TimeProvider.System);

        for (int i = 0; i < 3; i++)
        {
            await repo.IncrementDownloadCountByPurlAsync(_orgId, _purl);
        }

        await service.DrainPendingAsync();

        await using var conn = await _db.OpenAsync();
        // By-purl increments land in tenant_artifact_access.download_count (global plane).
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
        var service = new DownloadCountWriterHostedService(writer, _db,
            NullLogger<DownloadCountWriterHostedService>.Instance,
            TimeProvider.System);

        // Two uploaded-plane increments by versionId.
        await repo.IncrementDownloadCountAsync(_versionId);
        await repo.IncrementDownloadCountAsync(_versionId);
        // One global-plane increment by orgId+purl.
        await repo.IncrementDownloadCountByPurlAsync(_orgId, _purl);

        await service.DrainPendingAsync();

        await using var conn = await _db.OpenAsync();
        // Uploaded plane: package_versions gets the 2 versionId increments.
        int pvCount = await conn.ExecuteScalarAsync<int>(
            "SELECT download_count FROM package_versions WHERE id = @id",
            new { id = _versionId });
        Assert.Equal(2, pvCount);

        // Global plane: tenant_artifact_access gets the 1 purl increment.
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
