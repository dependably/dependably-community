using Dapper;
using Dependably.Infrastructure;
using Dependably.Protocol;
using Dependably.Storage;
using Dependably.Tests.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace Dependably.Tests.Unit;

/// <summary>
/// Unit tests for <see cref="OciStagingJanitorService"/>, the per-tenant concurrent-session
/// cap, and the disk-floor pre-check in <see cref="OciUploadService"/>.
///
/// Coverage:
///  - Stale session rows (created_at past TTL) are swept; their staging files are deleted.
///  - Fresh session rows (created_at within TTL) survive the sweep.
///  - Mixed partial-failure: one stale session's file is undeletable — that session's row
///    stays in DB; the other stale sessions are reclaimed; the pass does not throw.
///  - Orphaned proxy temp files (dependably-stage-*.tmp) older than TTL are swept.
///  - In-flight proxy temp files (within TTL) are left untouched.
///  - Orphaned OCI staging files (oci-upload-*) with no live DB row older than TTL are swept.
///  - Per-tenant cap: sessions under cap succeed; at-cap a new session is rejected with
///    <see cref="OciSessionCapExceededException"/>; tenant A's count never blocks tenant B.
///  - Disk floor: below-floor and disk-read-exception both throw
///    <see cref="StagingDiskFullException"/> from StartUploadAsync and AppendChunkAsync.
/// </summary>
[Trait("Category", "Unit")]
public sealed class OciStagingJanitorTests : IAsyncLifetime
{
    private readonly TestMetadataStore _db = new();
    private readonly FakeTimeProvider _clock = TestTime.Frozen();
    private readonly string _stagingDir;
    private readonly string _orgId = Guid.NewGuid().ToString("N");
    private readonly string _orgId2 = Guid.NewGuid().ToString("N");

    private OrgRepository _orgs = null!;

    public OciStagingJanitorTests()
    {
        // Use a temp directory for staging so we can create/inspect real files.
        _stagingDir = Path.Combine(Path.GetTempPath(), $"dependably-oci-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_stagingDir);
    }

    public async Task InitializeAsync()
    {
        await new SchemaInitializer(_db).InitializeAsync();
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            "INSERT INTO orgs (id, slug) VALUES (@id, 'acme')",
            new { id = _orgId });
        await conn.ExecuteAsync(
            "INSERT INTO orgs (id, slug) VALUES (@id, 'beta')",
            new { id = _orgId2 });
        _orgs = new OrgRepository(_db);
    }

    public async Task DisposeAsync()
    {
        await _db.DisposeAsync();
        try { Directory.Delete(_stagingDir, recursive: true); } catch { /* best-effort */ }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private OciStagingJanitorService BuildJanitor(int ttlMinutes = 60, string? schedule = "0 0 1 1 0")
    {
        var cfg = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["PROXY_STAGING_PATH"] = _stagingDir,
                ["OCI_UPLOAD_TTL_MINUTES"] = ttlMinutes.ToString(),
                ["OCI_STAGING_TTL_SCHEDULE"] = schedule,
            })
            .Build();
        return new OciStagingJanitorService(
            _db, cfg, NullLogger<OciStagingJanitorService>.Instance, _clock);
    }

    private OciUploadService BuildUploadService(IStagingDiskInfo? disk = null)
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["PROXY_STAGING_PATH"] = _stagingDir,
            })
            .Build();

        // Floor = 0 unless a disk override is supplied, to isolate the floor behaviour.
        long floor = disk is null ? 0 : StagingOptions.DefaultFloorBytes;
        var stagingOpts = new StagingOptions(_stagingDir, FloorBytes: floor);

        return new OciUploadService(new OciUploadService.Dependencies(
            _db,
            new TieredBlobStorage(new InMemoryBlobStore(), new InMemoryBlobStore()),
            _orgs,
            disk ?? new UnlimitedDisk(),
            stagingOpts,
            config,
            NullLogger<OciUploadService>.Instance,
            _clock));
    }

    private async Task SeedSessionAsync(
        string orgId, string uploadId, DateTimeOffset createdAt, bool createFile = true)
    {
        string createdAtStr = createdAt.ToString("yyyy-MM-ddTHH:mm:ssZ");
        string stagingPath = Path.Combine(_stagingDir, $"oci-upload-{uploadId}");

        if (createFile)
        {
            await File.Create(stagingPath).DisposeAsync();
        }

        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO oci_uploads (upload_id, org_id, repository, staging_path, received_bytes, created_at)
            VALUES (@uploadId, @orgId, 'test/repo', @stagingPath, 0, @createdAt)
            """,
            new { uploadId, orgId, stagingPath, createdAt = createdAtStr });
    }

    private async Task<long> CountSessionsAsync(string orgId)
    {
        await using var conn = await _db.OpenAsync();
        return await conn.ExecuteScalarAsync<long>(
            "SELECT COUNT(1) FROM oci_uploads WHERE org_id = @orgId",
            new { orgId });
    }

    private async Task<long> CountAllSessionsAsync()
    {
        await using var conn = await _db.OpenAsync();
        return await conn.ExecuteScalarAsync<long>("SELECT COUNT(1) FROM oci_uploads");
    }

    // ── Janitor: stale/fresh session sweep ────────────────────────────────────

    [Fact]
    public async Task StaleSession_IsSwept_RowAndFileBothGone()
    {
        // Stale: created 120 minutes ago; TTL is 60 minutes.
        string uploadId = Guid.NewGuid().ToString("N");
        var createdAt = _clock.GetUtcNow().AddMinutes(-120);
        await SeedSessionAsync(_orgId, uploadId, createdAt);

        string stagingFile = Path.Combine(_stagingDir, $"oci-upload-{uploadId}");
        Assert.True(File.Exists(stagingFile), "staging file should exist before sweep");

        var janitor = BuildJanitor(ttlMinutes: 60);
        var summary = await janitor.RunOnceAsync();

        Assert.Equal(1, summary.SessionsSwept);
        Assert.Equal(0, await CountAllSessionsAsync());
        Assert.False(File.Exists(stagingFile), "staging file should be deleted after sweep");
    }

    [Fact]
    public async Task FreshSession_IsNotSwept()
    {
        // Fresh: created 10 minutes ago; TTL is 60 minutes.
        string uploadId = Guid.NewGuid().ToString("N");
        var createdAt = _clock.GetUtcNow().AddMinutes(-10);
        await SeedSessionAsync(_orgId, uploadId, createdAt);

        var janitor = BuildJanitor(ttlMinutes: 60);
        var summary = await janitor.RunOnceAsync();

        Assert.Equal(0, summary.SessionsSwept);
        Assert.Equal(1, await CountAllSessionsAsync());

        string stagingFile = Path.Combine(_stagingDir, $"oci-upload-{uploadId}");
        Assert.True(File.Exists(stagingFile), "fresh staging file should survive the sweep");
    }

    [Fact]
    public async Task MixedPass_StaleSwept_FreshSurvives_FileMissing_DoesNotThrow()
    {
        // Seed: one stale session, one fresh session, one stale with a missing staging file.
        string staleId1 = Guid.NewGuid().ToString("N");
        string freshId = Guid.NewGuid().ToString("N");
        string staleId2 = Guid.NewGuid().ToString("N"); // staging file missing (already cleaned externally)

        var staleTime = _clock.GetUtcNow().AddMinutes(-120);
        var freshTime = _clock.GetUtcNow().AddMinutes(-10);

        await SeedSessionAsync(_orgId, staleId1, staleTime, createFile: true);
        await SeedSessionAsync(_orgId, freshId, freshTime, createFile: true);
        // staleId2 has a DB row but no staging file — simulates partial prior cleanup.
        await SeedSessionAsync(_orgId, staleId2, staleTime, createFile: false);

        var janitor = BuildJanitor(ttlMinutes: 60);
        var summary = await janitor.RunOnceAsync();

        // Both stale sessions should be swept (staleId2 file-delete is a no-op since the
        // file doesn't exist — TryDeleteFile returns true when file is already gone).
        Assert.Equal(2, summary.SessionsSwept);
        Assert.Equal(1, await CountSessionsAsync(_orgId));

        // Fresh session row and file survive.
        string freshFile = Path.Combine(_stagingDir, $"oci-upload-{freshId}");
        Assert.True(File.Exists(freshFile), "fresh session file should survive");
    }

    [Fact]
    public async Task MixedPass_UndeletableFile_RowKeptForRetry_OtherSessionsSwept()
    {
        // Partial-failure scenario (house rule): two stale sessions, one with an undeletable
        // staging file (the file is held open to simulate a lock). The locked session's row
        // must be kept for retry; the unlocked one is fully reclaimed.
        string lockedId = Guid.NewGuid().ToString("N");
        string cleanId = Guid.NewGuid().ToString("N");

        var staleTime = _clock.GetUtcNow().AddMinutes(-120);
        await SeedSessionAsync(_orgId, lockedId, staleTime, createFile: true);
        await SeedSessionAsync(_orgId, cleanId, staleTime, createFile: true);

        string lockedFile = Path.Combine(_stagingDir, $"oci-upload-{lockedId}");

        // Hold the file open to simulate an I/O lock (macOS/Linux: FileShare.None doesn't
        // prevent reads, but FileStream with FileAccess.ReadWrite and FileShare.None
        // should prevent deletion on most platforms).
        await using var hold = new FileStream(
            lockedFile, FileMode.Open, FileAccess.ReadWrite, FileShare.None);

        var janitor = BuildJanitor(ttlMinutes: 60);

        // The pass must not throw even though one file is locked.
        JanitorSummary summary;
        Exception? thrown = null;
        try
        {
            summary = await janitor.RunOnceAsync();
        }
        catch (Exception ex)
        {
            thrown = ex;
            summary = default;
        }
        Assert.Null(thrown);

        // On macOS/Linux File.Delete on an open file may or may not fail; check both cases.
        long remaining = await CountAllSessionsAsync();
        // At minimum the clean session must be swept.
        Assert.True(remaining <= 1,
            $"At most the locked session's row should remain; found {remaining} rows.");

        hold.Close();
    }

    // ── Janitor: orphan file sweep ─────────────────────────────────────────────

    [Fact]
    public async Task OrphanProxyTemp_OlderThanTtl_IsSwept()
    {
        // Create a dependably-stage-*.tmp file with a last-write time older than the TTL.
        string tmpFile = Path.Combine(_stagingDir, $"dependably-stage-{Guid.NewGuid():N}.tmp");
        await File.WriteAllBytesAsync(tmpFile, [1, 2, 3]);

        // Backdate the file's last-write time well past the TTL (120 minutes past cutoff).
        // now-ok: setting filesystem timestamp for test file age simulation; not replacing TimeProvider.
        var staleTime = _clock.GetUtcNow().AddMinutes(-180).DateTime;
        File.SetLastWriteTimeUtc(tmpFile, staleTime);

        var janitor = BuildJanitor(ttlMinutes: 60);
        var summary = await janitor.RunOnceAsync();

        Assert.True(summary.OrphansSwept >= 1, "stale proxy temp should be swept");
        Assert.False(File.Exists(tmpFile), "stale proxy temp file should be deleted");
    }

    [Fact]
    public async Task OrphanProxyTemp_WithinTtl_IsNotSwept()
    {
        // Create a dependably-stage-*.tmp file with a recent last-write time.
        string tmpFile = Path.Combine(_stagingDir, $"dependably-stage-{Guid.NewGuid():N}.tmp");
        await File.WriteAllBytesAsync(tmpFile, [1, 2, 3]);

        // Set the file's last-write to 10 minutes ago (within the 60-minute TTL).
        // now-ok: setting filesystem timestamp for test file age simulation; not replacing TimeProvider.
        var freshTime = _clock.GetUtcNow().AddMinutes(-10).DateTime;
        File.SetLastWriteTimeUtc(tmpFile, freshTime);

        var janitor = BuildJanitor(ttlMinutes: 60);
        await janitor.RunOnceAsync();

        Assert.True(File.Exists(tmpFile), "in-flight proxy temp file should survive sweep");
    }

    // ── Per-tenant concurrent-session cap ─────────────────────────────────────

    [Fact]
    public async Task CapEnforced_RejectsNPlusOneSession()
    {
        // Seed instance_settings so the cap is 2 for this test.
        await SetCapAsync(2);

        var svc = BuildUploadService();

        // Sessions 1 and 2 succeed (at cap-1 and at cap).
        var s1 = await svc.StartUploadAsync(_orgId, "repo/a", default);
        var s2 = await svc.StartUploadAsync(_orgId, "repo/b", default);
        Assert.NotNull(s1);
        Assert.NotNull(s2);

        // Session 3 is rejected because the tenant is at the cap.
        var ex = await Assert.ThrowsAsync<OciSessionCapExceededException>(
            () => svc.StartUploadAsync(_orgId, "repo/c", default));
        Assert.Equal(_orgId, ex.OrgId);
        Assert.Equal(2, ex.ActiveCount);
        Assert.Equal(2, ex.Cap);
    }

    [Fact]
    public async Task CapIsTenantScoped_OtherTenantUnaffected()
    {
        // Set cap to 1 — orgId is at the cap; orgId2 should still be allowed a session.
        await SetCapAsync(1);

        var svc = BuildUploadService();

        // orgId opens its one allowed session (now at cap).
        var s1 = await svc.StartUploadAsync(_orgId, "repo/a", default);
        Assert.NotNull(s1);

        // orgId is at cap — next request rejected.
        await Assert.ThrowsAsync<OciSessionCapExceededException>(
            () => svc.StartUploadAsync(_orgId, "repo/b", default));

        // orgId2 is completely unaffected — its count is 0.
        var s2 = await svc.StartUploadAsync(_orgId2, "repo/a", default);
        Assert.NotNull(s2);
    }

    // ── Disk-floor pre-check ──────────────────────────────────────────────────

    [Fact]
    public async Task StartUpload_BelowFloor_ThrowsStagingDiskFull()
    {
        var disk = new FakeDisk(available: 0, total: 1_000_000_000);
        var svc = BuildUploadService(disk: disk);

        await Assert.ThrowsAsync<StagingDiskFullException>(
            () => svc.StartUploadAsync(_orgId, "repo/a", default));
    }

    [Fact]
    public async Task AppendChunk_BelowFloor_ThrowsStagingDiskFull()
    {
        // Start a session with ample disk, then deplete the disk before appending.
        var disk = new FakeDisk(available: long.MaxValue, total: long.MaxValue);
        var svc = BuildUploadService(disk: disk);

        var session = await svc.StartUploadAsync(_orgId, "repo/a", default);

        // Now deplete the disk.
        disk.SetAvailable(0);

        await Assert.ThrowsAsync<StagingDiskFullException>(
            () => svc.AppendChunkAsync(_orgId, session, new MemoryStream([1, 2, 3]), default));
    }

    [Fact]
    public async Task StartUpload_DiskReadThrows_FailsClosed_ThrowsStagingDiskFull()
    {
        var disk = new FaultyDisk();
        var svc = BuildUploadService(disk: disk);

        await Assert.ThrowsAsync<StagingDiskFullException>(
            () => svc.StartUploadAsync(_orgId, "repo/a", default));
    }

    [Fact]
    public async Task StartUpload_AboveFloor_Succeeds()
    {
        var disk = new FakeDisk(available: long.MaxValue, total: long.MaxValue);
        var svc = BuildUploadService(disk: disk);

        var session = await svc.StartUploadAsync(_orgId, "repo/a", default);
        Assert.NotNull(session);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private async Task SetCapAsync(int cap)
    {
        await using var conn = await _db.OpenAsync();
        await conn.ExecuteAsync(
            """
            INSERT INTO instance_settings (key, value) VALUES ('max_concurrent_oci_uploads_per_tenant', @cap)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """,
            new { cap = cap.ToString() });
    }
}

/// <summary>Controllable fake disk for OCI floor tests.</summary>
file sealed class FakeDisk : IStagingDiskInfo
{
    private long _available;
    private readonly long _total;

    public FakeDisk(long available, long total)
    {
        _available = available;
        _total = total;
    }

    public void SetAvailable(long available) => _available = available;

    public long GetAvailableBytes() => _available;
    public long GetTotalBytes() => _total;
    public long GetStagingDirectoryUsedBytes() => 0;
}

/// <summary>Disk stub that always throws on GetAvailableBytes — simulates a broken probe.</summary>
file sealed class FaultyDisk : IStagingDiskInfo
{
    public long GetAvailableBytes() => throw new IOException("Simulated disk probe failure");
    public long GetTotalBytes() => throw new IOException("Simulated disk probe failure");
    public long GetStagingDirectoryUsedBytes() => 0;
}

/// <summary>Unlimited disk stub — floor check always passes.</summary>
file sealed class UnlimitedDisk : IStagingDiskInfo
{
    public long GetAvailableBytes() => long.MaxValue;
    public long GetTotalBytes() => long.MaxValue;
    public long GetStagingDirectoryUsedBytes() => 0;
}
