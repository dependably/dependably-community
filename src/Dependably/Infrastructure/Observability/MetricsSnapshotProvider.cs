namespace Dependably.Infrastructure.Observability;

/// <summary>
/// Assembles the lightweight operator-facing snapshot that the sysadmin
/// observability page (<c>SystemController.GET /api/v1/system/observability</c>)
/// returns. All values come from in-memory state populated by the
/// existing pollers (<c>TenantCountPoller</c>, <c>BlobStoreSizePoller</c>,
/// <c>BackgroundJobScope</c>) and the lifetime <see cref="SnapshotCounters"/>.
///
/// <para><b>No DB hits, no OTel SDK introspection.</b> Per the design
/// constraint that this page must not become an accidental polling
/// amplifier — every value is read directly from a static dictionary or
/// an interlocked counter. Page refresh cost is a few hash-table reads.</para>
///
/// <para>Numbers carry honest semantic labels: gauge values are
/// "current" (with the underlying poller interval noted in the doc);
/// counters are "since startup" — no fake rolling windows.</para>
/// </summary>
public sealed class MetricsSnapshotProvider
{
    public Snapshot Capture()
    {
        var blobSizes = DependablyMeter.ReadBlobStoreSizes();
        var jobLastSuccess = DependablyMeter.ReadBackgroundJobLastSuccess();

        return new Snapshot(
            ActiveTenants: DependablyMeter.ReadTenantCount(),
            BlobStoreSizesByTier: blobSizes,
            BackgroundJobLastSuccessUnixSeconds: jobLastSuccess,
            PublishCountSinceStartup: SnapshotCounters.PublishCount,
            ProxyFetchCountSinceStartup: SnapshotCounters.ProxyFetchCount,
            CacheHitsSinceStartup: SnapshotCounters.CacheHits,
            CacheMissesSinceStartup: SnapshotCounters.CacheMisses,
            CapturedAt: DateTimeOffset.UtcNow);
    }

    public sealed record Snapshot(
        long ActiveTenants,
        IReadOnlyDictionary<string, long> BlobStoreSizesByTier,
        IReadOnlyDictionary<string, long> BackgroundJobLastSuccessUnixSeconds,
        long PublishCountSinceStartup,
        long ProxyFetchCountSinceStartup,
        long CacheHitsSinceStartup,
        long CacheMissesSinceStartup,
        DateTimeOffset CapturedAt);
}
