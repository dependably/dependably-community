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

    public static readonly Counter<long> RpmRepomdSignatureFailures =
        Meter.CreateCounter<long>(
            "dependably.rpm.repomd_signature_failures",
            description: "RPM repomd.xml detached OpenPGP signature verification failures. " +
                         "Attributes: reason (missing_signature|bad_signature|no_trusted_key).");

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

    /// <summary>
    /// Download-count increments dropped because the async writer channel was full.
    /// Dropped increments mean the durable counter is slightly understated — acceptable
    /// under extreme load. Operators should watch this counter to detect sustained
    /// writer backpressure.
    /// </summary>
    public static readonly Counter<long> DownloadCountWriterDropped =
        Meter.CreateCounter<long>(
            "dependably.download_count_writer.dropped",
            description: "Download-count increments dropped because the async writer channel was full.");

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

    /// <summary>
    /// Downloads blocked because the version carries an OSV malicious-package advisory
    /// (<c>MAL-</c> id) and the tenant's <c>block_malicious</c> policy is 'block'.
    /// Attributes: <c>ecosystem</c>.
    /// </summary>
    public static readonly Counter<long> MaliciousBlocks =
        Meter.CreateCounter<long>(
            "dependably.security.malicious_blocks",
            description: "Downloads blocked by the block_malicious proxy policy. Attributes: ecosystem.");

    /// <summary>
    /// Downloads blocked because an advisory aliases a CISA-KEV-listed CVE and the tenant's
    /// <c>block_kev</c> policy is 'block'. Attributes: <c>ecosystem</c>.
    /// </summary>
    public static readonly Counter<long> KevBlocks =
        Meter.CreateCounter<long>(
            "dependably.security.kev_blocks",
            description: "Downloads blocked by the block_kev proxy policy. Attributes: ecosystem.");

    /// <summary>
    /// Upstream requests shed because the connection-pool wait-queue depth exceeded the
    /// process limit. The request is rejected immediately with 503 rather than queued
    /// indefinitely. No attributes — cardinality stays at 1.
    /// </summary>
    public static readonly Counter<long> UpstreamQueueSheds =
        Meter.CreateCounter<long>(
            "dependably.upstream.queue_sheds",
            description: "Upstream requests shed by the queue-depth throttle (503 returned immediately).");

    /// <summary>
    /// Downloads blocked because the version's maximum EPSS exploitation probability exceeds
    /// the tenant's <c>max_epss_tolerance</c> ceiling. Attributes: <c>ecosystem</c>.
    /// </summary>
    public static readonly Counter<long> EpssBlocks =
        Meter.CreateCounter<long>(
            "dependably.security.epss_blocks",
            description: "Downloads blocked by the max_epss_tolerance proxy policy. Attributes: ecosystem.");

    /// <summary>
    /// Downloads blocked because the version ships an install/lifecycle script and the tenant's
    /// <c>block_install_scripts</c> policy is 'block'. Attributes: <c>ecosystem</c>.
    /// </summary>
    public static readonly Counter<long> InstallScriptBlocks =
        Meter.CreateCounter<long>(
            "dependably.security.install_script_blocks",
            description: "Downloads blocked by the block_install_scripts proxy policy. Attributes: ecosystem.");

    /// <summary>
    /// Outcome of an artefact-provenance/signature check at proxy ingest. Attributes:
    /// <c>ecosystem</c> and <c>result</c> (<c>verified</c> / <c>failed</c> / <c>unsigned</c>).
    /// Deliberately carries no per-package labels — package name and version would blow the
    /// cardinality budget.
    /// </summary>
    public static readonly Counter<long> ProvenanceVerified =
        Meter.CreateCounter<long>(
            "dependably.security.provenance_verified",
            description: "Artefact provenance/signature checks at ingest. Attributes: ecosystem, result.");

    /// <summary>
    /// Downloads refused because provenance verification failed or was missing under a tenant
    /// require policy (the block-gate Provenance arm). Attributes: <c>ecosystem</c>.
    /// </summary>
    public static readonly Counter<long> ProvenanceBlocks =
        Meter.CreateCounter<long>(
            "dependably.security.provenance_blocks",
            description: "Downloads blocked by the verify-signatures proxy policy. Attributes: ecosystem.");

    /// <summary>
    /// First-fetch content-divergence events on the shared cache plane: a tenant fetched bytes
    /// whose SHA-256 differs from the already-cached global row for the same coordinate. Signals
    /// that two organisations resolved different bytes for the same (ecosystem, name, version,
    /// filename) tuple — typically because their upstream registries returned different content.
    /// Attributes: <c>ecosystem</c>. No per-tenant or per-package labels (cardinality budget).
    /// </summary>
    public static readonly Counter<long> CacheContentDivergences =
        Meter.CreateCounter<long>(
            "dependably.cache.content_divergences",
            description: "First-fetch content divergences on the shared cache plane: a tenant's fetched SHA-256 differs from the cached global row. Attributes: ecosystem.");

    // ── Foundation instruments — declared here; emission wired in follow-up ──

    /// <summary>
    /// Search and autocomplete request latency. Attributes: <c>ecosystem</c>,
    /// <c>operation</c> (search|autocomplete), <c>outcome</c>.
    /// </summary>
    public static readonly Histogram<double> SearchDuration =
        Meter.CreateHistogram<double>(
            "dependably.search.duration",
            unit: "s",
            description: "Search and autocomplete request latency in seconds. Attributes: ecosystem, operation (search|autocomplete), outcome.");

    /// <summary>
    /// Metadata document build latency. Attributes: <c>ecosystem</c>,
    /// <c>document</c> (simple_index|package_index|registration_index|registration_leaf|rpm_primary|rpm_filelists|rpm_other|rpm_merged_primary|rpm_merged_filelists|maven_metadata),
    /// <c>outcome</c>.
    /// </summary>
    public static readonly Histogram<double> MetadataBuildDuration =
        Meter.CreateHistogram<double>(
            "dependably.metadata.build.duration",
            unit: "s",
            description: "Metadata document build latency in seconds. Attributes: ecosystem, document (simple_index|package_index|registration_index|registration_leaf|rpm_primary|rpm_filelists|rpm_other|rpm_merged_primary|rpm_merged_filelists|maven_metadata), outcome.");

    /// <summary>
    /// Blob-store operation-initiation latency (open/seek/stat/connect). Measures the time
    /// to initiate the operation, NOT stream transfer time — the returned stream is drained
    /// later by the caller; end-to-end transfer is already captured by the HTTP span.
    /// Attributes: <c>operation</c> (get|put|exists|range|delete), <c>backend</c>
    /// (local|s3|azure), <c>outcome</c>.
    /// </summary>
    public static readonly Histogram<double> BlobStoreOperationDuration =
        Meter.CreateHistogram<double>(
            "dependably.blobstore.operation.duration",
            unit: "s",
            description: "Blob-store operation-initiation latency in seconds (open/seek/stat/connect). Measures operation-initiation latency, NOT stream transfer time. Attributes: operation (get|put|exists|range|delete), backend (local|s3|azure), outcome.");

    /// <summary>
    /// Token-auth resolve latency. Reuses the outcome vocabulary already used by the
    /// existing <see cref="TokenAuthRequests"/> counter: <c>success</c>, <c>invalid</c>,
    /// <c>no_auth</c>. Attribute: <c>outcome</c>.
    /// </summary>
    public static readonly Histogram<double> TokenAuthResolveDuration =
        Meter.CreateHistogram<double>(
            "dependably.token_auth.resolve.duration",
            unit: "s",
            description: "Token-auth resolve latency in seconds. Attribute: outcome (success|invalid|no_auth).");

    /// <summary>
    /// Async writer flush duration. Attributes: <c>writer</c> (download_count|activity),
    /// <c>outcome</c>.
    /// </summary>
    public static readonly Histogram<double> WriterFlushDuration =
        Meter.CreateHistogram<double>(
            "dependably.writer.flush.duration",
            unit: "s",
            description: "Async writer flush duration in seconds. Attributes: writer (download_count|activity), outcome.");

    /// <summary>
    /// Number of records flushed in a single async writer flush pass. Attribute:
    /// <c>writer</c> (download_count|activity).
    /// </summary>
    public static readonly Histogram<long> WriterFlushBatchSize =
        Meter.CreateHistogram<long>(
            "dependably.writer.flush.batch_size",
            unit: "{record}",
            description: "Number of records flushed in a single async writer flush pass. Attribute: writer (download_count|activity).");

    // ── Observable gauges — values pushed from elsewhere, read on scrape ────

    /// <summary>Background-job last-success unix timestamps, keyed by job_name.</summary>
    private static readonly ConcurrentDictionary<string, long> BackgroundJobLastSuccess = new();

    /// <summary>Blob-store size in bytes per tier (cache|registry); written by BlobStoreSizePoller.</summary>
    private static readonly ConcurrentDictionary<string, long> BlobStoreSizes = new();

    /// <summary>Active (non-soft-deleted) tenant count; written by TenantCountPoller.</summary>
    private static long _tenantCount;

    /// <summary>Available free bytes on the staging volume; written by StagingDiskMonitor.</summary>
    private static long _stagingDiskAvailableBytes;

    /// <summary>Bytes used by files in the staging directory; written by StagingDiskMonitor.</summary>
    private static long _stagingDiskUsedBytes;

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

        Meter.CreateObservableGauge(
            "dependably.staging.disk.available_bytes",
            observeValue: () => Interlocked.Read(ref _stagingDiskAvailableBytes),
            unit: "By",
            description: "Available free bytes on the staging volume. Updated by StagingDiskMonitor.");

        Meter.CreateObservableGauge(
            "dependably.staging.disk.used_bytes",
            observeValue: () => Interlocked.Read(ref _stagingDiskUsedBytes),
            unit: "By",
            description: "Bytes used by files currently present in the staging directory. Updated by StagingDiskMonitor.");
    }

    /// <summary>
    /// Records the most recent successful run of a background job for the
    /// observable gauge <c>dependably.background_job.last_success_timestamp</c>.
    /// Called by <see cref="BackgroundJobScope.Complete"/>, which supplies the
    /// timestamp from its clock — static meter helpers never read the wall clock.
    /// </summary>
    public static void RecordBackgroundJobSuccess(string jobName, long unixSeconds)
        => BackgroundJobLastSuccess[jobName] = unixSeconds;

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

    /// <summary>
    /// Records available bytes on the staging volume for the observable gauge
    /// <c>dependably.staging.disk.available_bytes</c>. Called by
    /// <c>StagingDiskMonitor</c>; values are stale up to the poll interval.
    /// </summary>
    public static void RecordStagingDiskAvailable(long bytes)
        => Interlocked.Exchange(ref _stagingDiskAvailableBytes, bytes);

    /// <summary>
    /// Records bytes used by files in the staging directory for the observable gauge
    /// <c>dependably.staging.disk.used_bytes</c>. Called by
    /// <c>StagingDiskMonitor</c>; values are stale up to the poll interval.
    /// </summary>
    public static void RecordStagingDiskUsed(long bytes)
        => Interlocked.Exchange(ref _stagingDiskUsedBytes, bytes);

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
