using System.Collections.Concurrent;
using System.Diagnostics.Metrics;

namespace Dependably.Infrastructure.Observability;

/// <summary>
/// Single OpenTelemetry <see cref="Meter"/> for every dependably-emitted
/// instrument. Names follow the canonical taxonomy
/// (<c>dependably.&lt;subsystem&gt;.&lt;noun&gt;[.&lt;unit&gt;]</c>) — see
/// <c>dependably-enterprise/docs/observability/taxonomy.md#metric-naming</c>.
///
/// Cardinality rule: instruments never carry <c>tenant_id</c>, <c>org_id</c>,
/// <c>email</c>, <c>user_id</c>, <c>purl</c>, <c>sha256</c>, or
/// <c>ip_address</c> as attributes. The CardinalityBudgetTests enforces this
/// — adding such an attribute will fail the build.
/// </summary>
public static class DependablyMeter
{
    public const string MeterName = "dependably";

    public static readonly Meter Meter = new(MeterName);

    // ── Migrated from prometheus-net (PR 2) ──────────────────────────────────

    public static readonly Counter<long> UpstreamUrlBlocks =
        Meter.CreateCounter<long>(
            "dependably.security.upstream_url_blocks",
            description: "Upstream URLs blocked by SSRF protection. Attributes: reason.");

    public static readonly Counter<long> AllowlistBlocks =
        Meter.CreateCounter<long>(
            "dependably.security.allowlist_blocks",
            description: "Package fetches blocked by allowlist mode. Attributes: ecosystem.");

    public static readonly Counter<long> UpstreamChecksumFailures =
        Meter.CreateCounter<long>(
            "dependably.upstream.checksum_failures",
            description: "Upstream artifact checksum mismatches. Attributes: ecosystem.");

    public static readonly UpDownCounter<long> UpstreamInflightFetches =
        Meter.CreateUpDownCounter<long>(
            "dependably.upstream.inflight_fetches",
            description: "Upstream fetches currently in flight. Attributes: ecosystem.");

    /// <summary>
    /// Maven artifact fetch bailed out because the SHA-256 sidecar was unavailable or
    /// verification was explicitly disabled. UpstreamClient routing requires a known
    /// content-addressed key, so the fetcher cannot proceed without a sidecar. Attributes:
    /// <c>reason</c> (<c>verify_disabled</c>|<c>sidecar_unavailable</c>) — bounded set.
    /// </summary>
    public static readonly Counter<long> MavenSidecarMissing =
        Meter.CreateCounter<long>(
            "dependably.maven.sidecar_missing",
            description: "Maven artifact fetch bailed out because sidecar SHA-256 was unavailable or verification disabled. Attributes: reason.");

    public static readonly Counter<long> AuditEmitFailures =
        Meter.CreateCounter<long>(
            "dependably.audit.emit_failures",
            description: "Audit-event emission failures. Attributes: event_type.");

    public static readonly Counter<long> HealthcheckPings =
        Meter.CreateCounter<long>(
            "dependably.healthcheck.pings",
            description: "Outbound healthcheck ping attempts. Attributes: outcome.");

    public static readonly Histogram<double> HealthcheckPingDuration =
        Meter.CreateHistogram<double>(
            "dependably.healthcheck.ping_duration",
            unit: "s",
            description: "Outbound healthcheck ping duration in seconds.");

    // ── New instruments declared in PR 2; emission lands in PR 3 / follow-up
    //    where the data source is wired. See observability/metrics.md. ──────

    public static readonly Counter<long> CacheLookups =
        Meter.CreateCounter<long>(
            "dependably.cache.lookups",
            description: "Proxy-cache lookups. Attributes: ecosystem, outcome (hit|miss).");

    public static readonly Histogram<double> UpstreamFetchDuration =
        Meter.CreateHistogram<double>(
            "dependably.upstream.fetch.duration",
            unit: "s",
            description: "Upstream fetch latency in seconds. Attributes: ecosystem, outcome.");

    public static readonly Histogram<double> PublishDuration =
        Meter.CreateHistogram<double>(
            "dependably.publish.duration",
            unit: "s",
            description: "Hosted-publish latency in seconds. Attributes: ecosystem, outcome.");

    public static readonly Histogram<long> PublishSizeBytes =
        Meter.CreateHistogram<long>(
            "dependably.publish.size_bytes",
            unit: "By",
            description: "Hosted-publish artifact size in bytes. Attributes: ecosystem.");

    public static readonly Histogram<double> BackgroundJobDuration =
        Meter.CreateHistogram<double>(
            "dependably.background_job.duration",
            unit: "s",
            description: "Background-job tick duration in seconds. Attributes: job_name, outcome.");

    public static readonly Counter<long> TokenAuthRequests =
        Meter.CreateCounter<long>(
            "dependably.token_auth.requests",
            description: "Token-auth attempts. Attributes: outcome.");

    /// <summary>
    /// Activity rows dropped because the async writer channel was full. Watch this
    /// counter to know when the writer has fallen behind sustained download throughput —
    /// activity rows are observability, not audit, so shedding under load is fine, but
    /// operators should see when it's happening.
    /// </summary>
    public static readonly Counter<long> ActivityWriterDropped =
        Meter.CreateCounter<long>(
            "dependably.activity_writer.dropped",
            description: "Activity records dropped because the async writer channel was full.");

    public static readonly Counter<long> ScanFindings =
        Meter.CreateCounter<long>(
            "dependably.scan.findings",
            description: "Vuln-scan findings. Attributes: severity, ecosystem.");

    /// <summary>
    /// Requests rejected by the download / push rate limiters. Attributes:
    /// <c>policy</c> (download|push|...), <c>partition</c> prefix (<c>token:HHHH</c>
    /// or <c>ip:1.2.3.4</c>). Lets operators see when a single token is rate-locked
    /// and identify it via the 12-hex prefix without leaking the full hash.
    /// </summary>
    public static readonly Counter<long> RateLimitRejected =
        Meter.CreateCounter<long>(
            "dependably.rate_limit.rejected",
            description: "Requests rejected by rate limiting. Attributes: policy, partition.");

    /// <summary>
    /// Package versions whose deprecation status changed during a refresh pass.
    /// Attributes: <c>ecosystem</c>.
    /// </summary>
    public static readonly Counter<long> DeprecationRefreshUpdated =
        Meter.CreateCounter<long>(
            "dependably.deprecation_refresh.updated",
            description: "Package versions whose deprecation status changed during a refresh pass. Attributes: ecosystem.");

    /// <summary>
    /// Package versions checked during a deprecation refresh pass (changed + unchanged).
    /// Attributes: <c>ecosystem</c>.
    /// </summary>
    public static readonly Counter<long> DeprecationRefreshChecked =
        Meter.CreateCounter<long>(
            "dependably.deprecation_refresh.checked",
            description: "Package versions checked during a deprecation refresh pass. Attributes: ecosystem.");

    /// <summary>
    /// Downloads blocked because the version is upstream-deprecated and the tenant's
    /// <c>block_deprecated</c> policy is set to 'block'. Attributes: <c>ecosystem</c>.
    /// </summary>
    public static readonly Counter<long> DeprecatedBlocks =
        Meter.CreateCounter<long>(
            "dependably.security.deprecated_blocks",
            description: "Downloads blocked by the block_deprecated proxy policy. Attributes: ecosystem.");

    // ── Observable gauges — values pushed from elsewhere, read on scrape ────

    /// <summary>Background-job last-success unix timestamps, keyed by job_name.</summary>
    private static readonly ConcurrentDictionary<string, long> BackgroundJobLastSuccess = new();

    /// <summary>Blob-store size in bytes per tier (cache|registry); written by BlobStoreSizePoller.</summary>
    private static readonly ConcurrentDictionary<string, long> BlobStoreSizes = new();

    /// <summary>Active (non-soft-deleted) tenant count; written by TenantCountPoller.</summary>
    private static long _tenantCount;

    static DependablyMeter()
    {
        Meter.CreateObservableGauge(
            "dependably.background_job.last_success_timestamp",
            observeValues: () => BackgroundJobLastSuccess.Select(kv =>
                new Measurement<long>(
                    kv.Value,
                    new KeyValuePair<string, object?>("job_name", kv.Key))),
            unit: "s",
            description: "Unix timestamp of the most recent successful run, per background job.");

        Meter.CreateObservableGauge(
            "dependably.blob_store.size_bytes",
            observeValues: () => BlobStoreSizes.Select(kv =>
                new Measurement<long>(
                    kv.Value,
                    new KeyValuePair<string, object?>("tier", kv.Key))),
            unit: "By",
            description: "Total bytes held by each blob-store tier (cache|registry). Updated by BlobStoreSizePoller.");

        Meter.CreateObservableGauge(
            "dependably.tenants.count",
            observeValue: () => Interlocked.Read(ref _tenantCount),
            description: "Active (non-soft-deleted) tenant count. Updated by TenantCountPoller.");
    }

    /// <summary>
    /// Records the most recent successful run of a background job for the
    /// observable gauge <c>dependably.background_job.last_success_timestamp</c>.
    /// Called by <see cref="BackgroundJobScope.Complete"/>.
    /// </summary>
    public static void RecordBackgroundJobSuccess(string jobName)
        => BackgroundJobLastSuccess[jobName] = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

    /// <summary>
    /// Records the current size of a blob-store tier for the observable gauge
    /// <c>dependably.blob_store.size_bytes</c>. Called by
    /// <c>BlobStoreSizePoller</c>; values are stale up to the poll interval.
    /// </summary>
    public static void RecordBlobStoreSize(string tier, long bytes)
        => BlobStoreSizes[tier] = bytes;

    /// <summary>
    /// Records the active tenant count for the observable gauge
    /// <c>dependably.tenants.count</c>. Called by <c>TenantCountPoller</c>.
    /// </summary>
    public static void RecordTenantCount(long count)
        => Interlocked.Exchange(ref _tenantCount, count);

    // ── Read accessors for the in-app snapshot page ────────────────────────
    //
    // MetricsSnapshotProvider needs to display the same values the
    // observable gauges expose to /metrics scrapes. These accessors give
    // it read-only views of the cached state without going through the
    // OTel SDK introspection APIs (which aren't designed for this).

    public static long ReadTenantCount() => Interlocked.Read(ref _tenantCount);

    public static IReadOnlyDictionary<string, long> ReadBackgroundJobLastSuccess()
        => BackgroundJobLastSuccess.ToDictionary(kv => kv.Key, kv => kv.Value);

    public static IReadOnlyDictionary<string, long> ReadBlobStoreSizes()
        => BlobStoreSizes.ToDictionary(kv => kv.Key, kv => kv.Value);
}
