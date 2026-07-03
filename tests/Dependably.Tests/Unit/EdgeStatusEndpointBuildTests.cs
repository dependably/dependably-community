using Dependably.Api;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Observability;
using Dependably.Tests.Infrastructure;

namespace Dependably.Tests.Unit;

/// <summary>
/// Shape and redaction rules for the <c>/edge/status</c> payload, asserted through the pure
/// <see cref="EdgeStatusEndpoint.Build"/> builder so no host is needed. Covers the node section
/// (scheme+host only — never the token or a full credential-bearing URL), the disk figures
/// (numbers, no paths), and uptime derived from the injected clock.
/// </summary>
[Trait("Category", "Unit")]
public sealed class EdgeStatusEndpointBuildTests
{
    private sealed class StubDisk(long total, long available, long staging) : IStagingDiskInfo
    {
        public long GetAvailableBytes() => available;
        public long GetTotalBytes() => total;
        public long GetStagingDirectoryUsedBytes() => staging;
    }

    [Fact]
    public void Build_NodeSection_ExposesSchemeAndHostOnly_NeverTheToken()
    {
        var clock = TestTime.Frozen();
        var tracker = new EdgeStatusTracker(clock);
        var edge = TestEdgeMode.Edge("https://master.internal.example:8443", masterToken: "super-secret-edge-token");
        var startedAt = clock.GetUtcNow();

        clock.Advance(TimeSpan.FromSeconds(90));
        var payload = EdgeStatusEndpoint.Build(
            tracker, new StubDisk(1000, 400, 25), edge, clock, version: "9.9.9-test", startedAt);

        Assert.Equal("edge", payload.Node.DeploymentMode);
        // Host + scheme, no port-path-userinfo, and above all NO token anywhere.
        Assert.Equal("https://master.internal.example", payload.Node.MasterHost);
        Assert.DoesNotContain("super-secret-edge-token", payload.Node.MasterHost);
        Assert.Equal("9.9.9-test", payload.Node.Version);
        Assert.Equal(startedAt, payload.Node.StartedAt);
        Assert.Equal(90, payload.Node.UptimeSeconds);
    }

    [Fact]
    public void Build_ReachabilitySection_ReflectsTrackerState()
    {
        var clock = TestTime.Frozen();
        var tracker = new EdgeStatusTracker(clock);
        var edge = TestEdgeMode.Edge("https://m.example");

        // Unknown before any fetch.
        var before = EdgeStatusEndpoint.Build(
            tracker, new StubDisk(1, 1, 0), edge, clock, "v", clock.GetUtcNow());
        Assert.Equal("unknown", before.MasterReachability.State);
        Assert.Null(before.MasterReachability.LastSuccessfulPullAt);
        Assert.Null(before.MasterReachability.LastFailedPullAt);

        tracker.RecordSuccess();
        var afterSuccess = EdgeStatusEndpoint.Build(
            tracker, new StubDisk(1, 1, 0), edge, clock, "v", clock.GetUtcNow());
        Assert.Equal("ok", afterSuccess.MasterReachability.State);
        Assert.Equal(clock.GetUtcNow(), afterSuccess.MasterReachability.LastSuccessfulPullAt);

        clock.Advance(TimeSpan.FromMinutes(1));
        tracker.RecordFailure();
        var afterFailure = EdgeStatusEndpoint.Build(
            tracker, new StubDisk(1, 1, 0), edge, clock, "v", clock.GetUtcNow());
        Assert.Equal("degraded", afterFailure.MasterReachability.State);
        Assert.Equal(clock.GetUtcNow(), afterFailure.MasterReachability.LastFailedPullAt);
        Assert.NotNull(afterFailure.MasterReachability.LastSuccessfulPullAt);
    }

    [Fact]
    public void Build_DiskSection_ReportsNumbersFromStagingDiskInfo()
    {
        var clock = TestTime.Frozen();
        var edge = TestEdgeMode.Edge("https://m.example");

        var payload = EdgeStatusEndpoint.Build(
            new EdgeStatusTracker(clock), new StubDisk(total: 5000, available: 1234, staging: 77),
            edge, clock, "v", clock.GetUtcNow());

        Assert.Equal(5000, payload.Disk.CacheVolumeTotalBytes);
        Assert.Equal(1234, payload.Disk.CacheVolumeAvailableBytes);
        Assert.Equal(77, payload.Disk.StagingUsedBytes);
    }
}
