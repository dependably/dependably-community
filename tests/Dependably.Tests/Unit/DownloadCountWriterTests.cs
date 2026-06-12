using Dapper;
using Dependably.Infrastructure;
using Dependably.Tests.Infrastructure;
using Dependably.Tests.Infrastructure.Seeding;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit;

/// <summary>
/// Acceptance tests for <see cref="PackageRepository.IncrementDownloadCountAsync"/> and
/// <see cref="PackageRepository.IncrementDownloadCountByPurlAsync"/> off-path behaviour:
/// when a <see cref="DownloadCountWriter"/> is wired in, the hot path must enqueue without
/// touching the DB; the hosted-service drainer must aggregate and flush the counts.
/// </summary>
[Trait("Category", "Unit")]
public sealed class DownloadCountWriterTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private string _orgId = default!;
    private string _versionId = default!;
    private string _purl = default!;

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();

        _orgId = $"org-{Guid.NewGuid():N}";
        await conn.ExecuteAsync("INSERT INTO orgs (id, slug) VALUES (@id, @slug)",
            new { id = _orgId, slug = _orgId });

        string pkgId = $"pkg-{Guid.NewGuid():N}";
        _purl = $"pkg:npm/{Guid.NewGuid():N}/lib@1.0.0";
        await conn.ExecuteAsync(
            "INSERT INTO packages (id, org_id, ecosystem, name, purl_name) VALUES (@pkgId, @orgId, 'npm', 'lib', 'lib')",
            new { pkgId, orgId = _orgId });

        _versionId = $"ver-{Guid.NewGuid():N}";
        await conn.ExecuteAsync(
            """
            INSERT INTO package_versions
                (id, package_id, version, purl, blob_key, size_bytes, checksum_sha256)
            VALUES
                (@id, @pkgId, '1.0.0', @purl, 'registry/npm/lib/1.0.0/lib-1.0.0.tgz',
                 1000, 'aaaa')
            """,
            new { id = _versionId, pkgId, purl = _purl });
    }

    public async Task DisposeAsync() => await _db.DisposeAsync();

    // ── TryEnqueue ───────────────────────────────────────────────────────────

    [Fact]
    public void TryEnqueue_BelowCapacity_Returns_True()
    {
        var writer = new DownloadCountWriter();
        Assert.True(writer.TryEnqueue(new DownloadCountRecord(VersionId: "v1", Purl: null)));
    }

    [Fact]
    public void TryEnqueue_AtCapacity_DropsRecord_ReturnsFalse()
    {
        var writer = new DownloadCountWriter();
        for (int i = 0; i < DownloadCountWriter.ChannelCapacity; i++)
        {
            Assert.True(writer.TryEnqueue(new DownloadCountRecord(VersionId: $"v{i}", Purl: null)));
        }
        Assert.False(writer.TryEnqueue(new DownloadCountRecord(VersionId: "overflow", Purl: null)));
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

    [Fact]
    public async Task IncrementDownloadCountByPurlAsync_WithWriter_DoesNotWriteSynchronously()
    {
        var writer = new DownloadCountWriter();
        var repo = new PackageRepository(_db, writer);

        await repo.IncrementDownloadCountByPurlAsync(_purl);

        await using var conn = await _db.OpenAsync();
        int count = await conn.ExecuteScalarAsync<int>(
            "SELECT download_count FROM package_versions WHERE purl = @purl",
            new { purl = _purl });
        Assert.Equal(0, count);
    }

    [Fact]
    public async Task IncrementDownloadCountByPurlAsync_WithoutWriter_WritesSynchronously()
    {
        var repo = new PackageRepository(_db);

        await repo.IncrementDownloadCountByPurlAsync(_purl);

        await using var conn = await _db.OpenAsync();
        int count = await conn.ExecuteScalarAsync<int>(
            "SELECT download_count FROM package_versions WHERE purl = @purl",
            new { purl = _purl });
        Assert.Equal(1, count);
    }

    // ── DrainPendingAsync — aggregation and flush ─────────────────────────────

    [Fact]
    public async Task DrainPendingAsync_ByVersionId_AggregatesMultipleIncrementsIntoSingleUpdate()
    {
        var writer = new DownloadCountWriter();
        var repo = new PackageRepository(_db, writer);
        var service = new DownloadCountWriterHostedService(writer, _db,
            NullLogger<DownloadCountWriterHostedService>.Instance);

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
            NullLogger<DownloadCountWriterHostedService>.Instance);

        for (int i = 0; i < 3; i++)
        {
            await repo.IncrementDownloadCountByPurlAsync(_purl);
        }

        await service.DrainPendingAsync();

        await using var conn = await _db.OpenAsync();
        int count = await conn.ExecuteScalarAsync<int>(
            "SELECT download_count FROM package_versions WHERE purl = @purl",
            new { purl = _purl });
        Assert.Equal(3, count);
    }

    [Fact]
    public async Task DrainPendingAsync_OverMaxBatch_FlushesAllRecords()
    {
        // 250 records > MaxBatch(200) — drainer must not drop or block; it keeps flushing.
        var writer = new DownloadCountWriter();
        var repo = new PackageRepository(_db, writer);
        var service = new DownloadCountWriterHostedService(writer, _db,
            NullLogger<DownloadCountWriterHostedService>.Instance);

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
    public async Task DrainPendingAsync_MixedKeys_UpdatesBothVersionIdAndPurl()
    {
        var writer = new DownloadCountWriter();
        var repo = new PackageRepository(_db, writer);
        var service = new DownloadCountWriterHostedService(writer, _db,
            NullLogger<DownloadCountWriterHostedService>.Instance);

        await repo.IncrementDownloadCountAsync(_versionId);
        await repo.IncrementDownloadCountAsync(_versionId);
        await repo.IncrementDownloadCountByPurlAsync(_purl);

        await service.DrainPendingAsync();

        await using var conn = await _db.OpenAsync();
        // Both versionId and purl point to the same row, so the total is 3.
        int count = await conn.ExecuteScalarAsync<int>(
            "SELECT download_count FROM package_versions WHERE id = @id",
            new { id = _versionId });
        Assert.Equal(3, count);
    }
}
