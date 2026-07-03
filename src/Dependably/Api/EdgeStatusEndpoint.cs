using System.Text.Json;
using Dependably.Infrastructure;
using Dependably.Infrastructure.Observability;

namespace Dependably.Api;

/// <summary>
/// Read-only, anonymous status surface for a headless edge node: <c>GET /edge/status</c>. Mapped
/// ONLY when <see cref="IEdgeMode.IsEdge"/> — in every other deployment mode the route is never
/// registered (a request 404s), which also keeps it out of the non-edge OpenAPI documents and the
/// ApiContract gate. Follows the <c>/health</c> convention: anonymous, so the payload carries
/// nothing sensitive — no token material, no org data, no full upstream URL that could embed
/// credentials (host + scheme only), and disk figures rather than filesystem paths.
///
/// <para>Every field is derived from state the process already holds:
///   - master reachability from the passive <see cref="EdgeStatusTracker"/> (fed at the
///     <c>UpstreamClient</c> fetch boundary — no active probe fires from this endpoint),
///   - cache hit/miss from the process-lifetime <see cref="SnapshotCounters"/>,
///   - disk figures from the shared <see cref="IStagingDiskInfo"/> the staging monitor already uses,
///   - uptime/timestamps from the injected <see cref="TimeProvider"/>.</para>
/// </summary>
public static class EdgeStatusEndpoint
{
    // Frontend-facing JSON is camelCase (JsonSerializerDefaults.Web). This surface is operator/ops
    // JSON, but the same house rule applies so field names read consistently across the product.
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    /// <summary>
    /// Maps <c>GET /edge/status</c> when — and only when — the node runs in edge mode. The
    /// process start instant is captured once so uptime is measured against a fixed origin.
    /// </summary>
    public static void Map(WebApplication app, string version)
    {
        var edge = app.Services.GetRequiredService<IEdgeMode>();
        if (!edge.IsEdge)
        {
            return;
        }

        var time = app.Services.GetRequiredService<TimeProvider>();
        var startedAt = time.GetUtcNow();

        app.MapGet("/edge/status", (
            EdgeStatusTracker tracker,
            IStagingDiskInfo disk,
            IEdgeMode edgeMode,
            TimeProvider clock) =>
        {
            var payload = Build(tracker, disk, edgeMode, clock, version, startedAt);
            return Results.Json(payload, JsonOptions);
        })
        .RequireRateLimiting("anon")
        .ExcludeFromDescription();
    }

    /// <summary>
    /// Builds the status payload from the injected state sources. Pure given its inputs (aside from
    /// reading "now" off the clock) so a unit test can assert the exact shape without a host.
    /// </summary>
    public static EdgeStatusResponse Build(
        EdgeStatusTracker tracker,
        IStagingDiskInfo disk,
        IEdgeMode edge,
        TimeProvider clock,
        string version,
        DateTimeOffset startedAt)
    {
        var now = clock.GetUtcNow();

        long lastSuccessTicks = tracker.LastSuccessAtTicks;
        long lastFailureTicks = tracker.LastFailureAtTicks;

        var reachability = new EdgeMasterReachability(
            State: StateString(tracker.State),
            LastSuccessfulPullAt: TicksToTimestamp(lastSuccessTicks),
            LastFailedPullAt: TicksToTimestamp(lastFailureTicks));

        long hits = SnapshotCounters.CacheHits;
        long misses = SnapshotCounters.CacheMisses;
        var cache = new EdgeCacheStatus(
            Hits: hits,
            Misses: misses,
            HitRate: HitRate(hits, misses));

        var diskStatus = new EdgeDiskStatus(
            CacheVolumeTotalBytes: SafeDisk(disk.GetTotalBytes),
            CacheVolumeAvailableBytes: SafeDisk(disk.GetAvailableBytes),
            StagingUsedBytes: SafeDisk(disk.GetStagingDirectoryUsedBytes));

        // masterHost is host-only by construction (IEdgeMode.MasterHost); the scheme is
        // reattached so an operator can tell http from https without ever exposing a
        // credential-bearing userinfo component or path.
        string masterHost = ComposeMasterHost(edge.MasterUrl, edge.MasterHost);

        var node = new EdgeNodeStatus(
            DeploymentMode: "edge",
            MasterHost: masterHost,
            Version: version,
            StartedAt: startedAt,
            UptimeSeconds: (long)Math.Max(0, (now - startedAt).TotalSeconds));

        return new EdgeStatusResponse(reachability, cache, diskStatus, node);
    }

    private static string StateString(EdgeReachabilityState state) => state switch
    {
        EdgeReachabilityState.Ok => "ok",
        EdgeReachabilityState.Degraded => "degraded",
        _ => "unknown",
    };

    private static DateTimeOffset? TicksToTimestamp(long ticks) =>
        ticks == 0 ? null : new DateTimeOffset(ticks, TimeSpan.Zero);

    private static double HitRate(long hits, long misses)
    {
        long total = hits + misses;
        if (total <= 0)
        {
            return 0d;
        }

        // Round to 4 dp so the JSON is stable and readable; exact ratios are Grafana's job.
        return Math.Round((double)hits / total, 4);
    }

    // Disk reads can throw (volume unmounted mid-flight); a status endpoint must never 500 on that.
    private static long SafeDisk(Func<long> read)
    {
        try
        {
            return read();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return -1;
        }
    }

    private static string ComposeMasterHost(string masterUrl, string masterHost) =>
        string.IsNullOrEmpty(masterHost)
            ? ""
            : Uri.TryCreate(masterUrl, UriKind.Absolute, out var uri)
                ? $"{uri.Scheme}://{uri.Host}"
                : masterHost;
}

/// <summary>Top-level <c>/edge/status</c> payload (camelCase on the wire).</summary>
public sealed record EdgeStatusResponse(
    EdgeMasterReachability MasterReachability,
    EdgeCacheStatus Cache,
    EdgeDiskStatus Disk,
    EdgeNodeStatus Node);

/// <summary>
/// Passively-derived master reachability. <c>state</c> is <c>ok</c> when the most recent upstream
/// fetch succeeded, <c>degraded</c> when it failed, and <c>unknown</c> before any fetch. The two
/// timestamps are the last time each outcome was observed (null until it has happened at least once).
/// </summary>
public sealed record EdgeMasterReachability(
    string State,
    DateTimeOffset? LastSuccessfulPullAt,
    DateTimeOffset? LastFailedPullAt);

/// <summary>Cache hit/miss counts and hit rate since process start.</summary>
public sealed record EdgeCacheStatus(long Hits, long Misses, double HitRate);

/// <summary>
/// Cache-volume disk figures (bytes). A value of <c>-1</c> means the figure could not be read.
/// Paths are deliberately omitted — only numbers are reported.
/// </summary>
public sealed record EdgeDiskStatus(
    long CacheVolumeTotalBytes,
    long CacheVolumeAvailableBytes,
    long StagingUsedBytes);

/// <summary>Node identity and liveness. <c>masterHost</c> is scheme+host only — never the token or a full URL.</summary>
public sealed record EdgeNodeStatus(
    string DeploymentMode,
    string MasterHost,
    string Version,
    DateTimeOffset StartedAt,
    long UptimeSeconds);
