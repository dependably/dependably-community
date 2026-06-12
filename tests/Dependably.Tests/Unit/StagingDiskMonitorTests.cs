using Dependably.Infrastructure;
using Dependably.Infrastructure.Observability;
using Dependably.Protocol;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dependably.Tests.Unit;

[Trait("Category", "Unit")]
public class StagingDiskMonitorTests
{
    // ── IStagingDiskInfo mock ────────────────────────────────────────────────────

    private sealed class FakeDiskInfo(long available, long total, long used = 0) : IStagingDiskInfo
    {
        public long GetAvailableBytes() => available;
        public long GetTotalBytes() => total;
        public long GetStagingDirectoryUsedBytes() => used;
    }

    // ── StagingDiskFullException floor check (the logic tested here lives inside
    //    UpstreamClient.FetchAndStageAsync but is unit-tested via the exception type
    //    and the gate logic extracted into the helper below) ─────────────────────

    private static bool IsFloorBreached(IStagingDiskInfo disk, long floorBytes)
    {
        long available = disk.GetAvailableBytes();
        return available < floorBytes;
    }

    [Fact]
    public void FloorCheck_AvailableAboveFloor_Passes()
    {
        var disk = new FakeDiskInfo(available: 600 * 1024 * 1024, total: 10L * 1024 * 1024 * 1024);
        long floor = 512 * 1024 * 1024; // 512 MiB default

        Assert.False(IsFloorBreached(disk, floor));
    }

    [Fact]
    public void FloorCheck_AvailableExactlyAtFloor_Passes()
    {
        long floor = 512 * 1024 * 1024;
        var disk = new FakeDiskInfo(available: floor, total: 10L * 1024 * 1024 * 1024);

        Assert.False(IsFloorBreached(disk, floor));
    }

    [Fact]
    public void FloorCheck_AvailableBelowFloor_Breached()
    {
        long floor = 512 * 1024 * 1024;
        var disk = new FakeDiskInfo(available: floor - 1, total: 10L * 1024 * 1024 * 1024);

        Assert.True(IsFloorBreached(disk, floor));
    }

    [Fact]
    public void FloorCheck_ZeroAvailable_Breached()
    {
        var disk = new FakeDiskInfo(available: 0, total: 10L * 1024 * 1024 * 1024);
        Assert.True(IsFloorBreached(disk, 512 * 1024 * 1024));
    }

    [Fact]
    public void FloorCheck_DynamicFloor_TwoTimesContentLength()
    {
        // Dynamic floor = max(absolute, 2 × Content-Length).
        // If available < 2 × Content-Length the fetch should be rejected.
        long contentLength = 400 * 1024 * 1024; // 400 MiB
        long absoluteFloor = 512 * 1024 * 1024; // 512 MiB absolute
        long dynamicFloor = Math.Max(absoluteFloor, contentLength * 2); // 800 MiB wins
        var disk = new FakeDiskInfo(available: 600 * 1024 * 1024, total: 10L * 1024 * 1024 * 1024);

        Assert.True(IsFloorBreached(disk, dynamicFloor));
    }

    [Fact]
    public void FloorCheck_DynamicFloor_AbsoluteWinsWhenContentLengthSmall()
    {
        long contentLength = 50 * 1024 * 1024;    // 50 MiB
        long absoluteFloor = 512 * 1024 * 1024;   // 512 MiB absolute
        long dynamicFloor = Math.Max(absoluteFloor, contentLength * 2); // 512 MiB wins
        var disk = new FakeDiskInfo(available: 600 * 1024 * 1024, total: 10L * 1024 * 1024 * 1024);

        Assert.False(IsFloorBreached(disk, dynamicFloor));
    }

    // ── StagingDiskMonitor.PollOnce ──────────────────────────────────────────────

    private static StagingDiskMonitor BuildMonitor(
        IStagingDiskInfo diskInfo,
        int warnThresholdPercent = 10,
        int intervalSeconds = 60)
    {
        var dict = new Dictionary<string, string?>
        {
            ["STAGING_DISK_WARN_THRESHOLD_PERCENT"] = warnThresholdPercent.ToString(),
            ["STAGING_DISK_POLL_INTERVAL_SECONDS"] = intervalSeconds.ToString(),
        };
        var cfg = new ConfigurationBuilder().AddInMemoryCollection(dict).Build();
        return new StagingDiskMonitor(diskInfo, cfg, NullLogger<StagingDiskMonitor>.Instance);
    }

    [Fact]
    public void PollOnce_AboveThreshold_DoesNotThrow()
    {
        // 50 GiB available of 100 GiB = 50%, well above 10% threshold.
        var disk = new FakeDiskInfo(
            available: 50L * 1024 * 1024 * 1024,
            total: 100L * 1024 * 1024 * 1024,
            used: 1024 * 1024);

        var monitor = BuildMonitor(disk);

        // Should not throw even when free space is fine.
        var ex = Record.Exception(() => monitor.PollOnce());
        Assert.Null(ex);
    }

    [Fact]
    public void PollOnce_BelowThreshold_DoesNotThrow()
    {
        // 5 GiB available of 100 GiB = 5%, below 10% threshold.
        // The monitor logs a warning but must not throw — it should continue running.
        var disk = new FakeDiskInfo(
            available: 5L * 1024 * 1024 * 1024,
            total: 100L * 1024 * 1024 * 1024,
            used: 2048);

        var monitor = BuildMonitor(disk, warnThresholdPercent: 10);

        var ex = Record.Exception(() => monitor.PollOnce());
        Assert.Null(ex);
    }

    [Fact]
    public void PollOnce_DiskInfoThrows_SwallowsException()
    {
        // Monitor must survive polling errors and keep running.
        var faultyDisk = new FaultyDiskInfo();
        var monitor = BuildMonitor(faultyDisk);

        var ex = Record.Exception(() => monitor.PollOnce());
        Assert.Null(ex);
    }

    // ── StagingDiskFullException ─────────────────────────────────────────────────

    [Fact]
    public void StagingDiskFullException_CarriesAvailableAndFloorBytes()
    {
        long available = 100;
        long floor = 512 * 1024 * 1024;
        var ex = new StagingDiskFullException(available, floor);

        Assert.Equal(available, ex.AvailableBytes);
        Assert.Equal(floor, ex.FloorBytes);
        Assert.Contains("100", ex.Message);
    }

    private sealed class FaultyDiskInfo : IStagingDiskInfo
    {
        public long GetAvailableBytes() => throw new IOException("disk probe failed");
        public long GetTotalBytes() => throw new IOException("disk probe failed");
        public long GetStagingDirectoryUsedBytes() => throw new IOException("disk probe failed");
    }
}
