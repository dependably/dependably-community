using System.Globalization;
using Dependably.Infrastructure.Redis;
using Dependably.Infrastructure.RowLevelSecurity;
using Dependably.Infrastructure.SystemEvents;

namespace Dependably.Infrastructure;

/// <summary>
/// Hourly sweep (<c>CACHE_SIZE_ALERT_SCHEDULE</c>, default <c>0 * * * *</c>) that compares the
/// instance-wide proxy cache tier against an operator-configured warn threshold
/// (<c>instance_settings.cache_size_warn_bytes</c>, see <see cref="InstanceSettingDefaults"/>) and
/// alerts the apex/system admin exactly once per upward crossing.
///
/// <para>
/// The cache figure is measured from the database — <c>CacheArtifactRepository.GetTotalSizeBytesAsync</c>
/// plus <c>GetOciProxyOnlyDistinctDigestBytesAsync</c> — the same evictable-cache total
/// <c>CACHE_MAX_SIZE_BYTES</c> eviction is compared against, plus the OCI share that table cannot
/// see. This is deliberately <b>not</b> <c>dependably.blob_store.size_bytes{tier="cache"}</c>:
/// <c>BlobStoreSizePoller</c> only ever populates that gauge's <c>"cache"</c> label when
/// <c>TieredBlobStorage.IsSplit</c> is true, i.e. only when the operator has pointed the cache and
/// registry tiers at two different backing stores. A default, unsplit deployment — the common case
/// — never gets a <c>"cache"</c> gauge value at all, so reading it here would read zero forever and
/// the alert would never fire on the deployments most likely to run it unconfigured.
/// </para>
///
/// <para>
/// A crossing is durable: it is recorded in <c>instance_settings.cache_size_alert_crossed</c>, set
/// only <b>after</b> the audit row and the Slack notification both succeed — a tick that crashes
/// between measuring and notifying leaves the flag exactly where it was, so the next tick retries
/// the alert rather than silently losing it. A possible duplicate alert on a retried tick is the
/// accepted cost of never losing one outright. The most recently measured size and the instant it
/// was measured are persisted alongside it (<c>cache_size_last_bytes</c> /
/// <c>cache_size_last_measured_at</c>), so <c>HealthService</c> can report both without re-measuring
/// the cache tier on every health check.
/// </para>
///
/// <para>
/// A measurement that fails (the DB is unreachable, a query throws) is never treated as zero: the
/// tick logs a warning and returns without touching any persisted state, so a transient failure
/// neither fires a false re-arm nor a false crossing, and the next scheduled tick retries.
/// </para>
///
/// suspension-ok: not per-tenant. The cache tier is one shared, content-addressed store — there is
/// no per-org figure to gate.
/// </summary>
public sealed class CacheSizeAlertService : ScheduledBackgroundService
{
    internal const string JobName = "cache-size-alert";
    internal const string WarnBytesSettingKey = "cache_size_warn_bytes";
    internal const string CrossedStateSettingKey = "cache_size_alert_crossed";
    internal const string LastBytesSettingKey = "cache_size_last_bytes";
    internal const string LastMeasuredAtSettingKey = "cache_size_last_measured_at";

    private readonly OrgRepository _orgs;
    private readonly CacheArtifactRepository _cacheArtifacts;
    private readonly AuditRepository _audit;
    private readonly ISystemEventNotifier _systemEvents;
    private readonly IAirGapMode _airGap;
    private readonly ILogger<CacheSizeAlertService> _logger;
    private readonly TimeProvider _time;

    protected override string CronEnvKey => "CACHE_SIZE_ALERT_SCHEDULE";
    protected override string DefaultCron => "0 * * * *"; // hourly, on the hour
    protected override string ScopeJobName => JobName;
    protected override string ScopeMetricName => "cache.size_alert_check";

    // The crossed/re-armed state, and the last-measured figures, are shared, instance-wide data:
    // two replicas ticking independently would each measure and decide from a stale read, and could
    // race each other's writes. Only the leader ticks, exactly like UsageStorageSnapshotService's
    // shared storage_snapshot writes and CacheEvictionService's shared cache-tier sweep.
    protected override bool RequiresLeaderLock => true;

#pragma warning disable S107 // DI constructor — each dependency feeds one independent part of the check.
    public CacheSizeAlertService(
        OrgRepository orgs,
        CacheArtifactRepository cacheArtifacts,
        AuditRepository audit,
        ISystemEventNotifier systemEvents,
        IAirGapMode airGap,
        IConfiguration config,
        ILogger<CacheSizeAlertService> logger,
        TimeProvider time,
        IDistributedLock locks)
        : base(config, logger, time, locks)
#pragma warning restore S107
    {
        _orgs = orgs;
        _cacheArtifacts = cacheArtifacts;
        _audit = audit;
        _systemEvents = systemEvents;
        _airGap = airGap;
        _logger = logger;
        _time = time;
    }

    protected override Task RunTickAsync(CancellationToken ct) => RunCheckPassAsync(ct);

    // internal (not private) so tests can drive a pass directly without the cron/leader-lock
    // scheduling machinery, mirroring UsageStorageSnapshotService.RunPassAsync.
    internal async Task RunCheckPassAsync(CancellationToken ct)
    {
        if (_airGap.IsJobDisabled(JobName))
        {
            _logger.LogInformation(
                "Cache-size alert check skipped (disabled by AIR_GAPPED or DISABLE_BACKGROUND_JOBS).");
            return;
        }

        // xtenant: the proxy cache is one shared, content-addressed plane across every tenant —
        // sizing it means summing every org's rows, exactly like CacheEvictionService's own pass.
        using var ownerScope = DbScope.CrossTenant("cache size alert");

        long cacheBytes;
        try
        {
            cacheBytes = await MeasureCacheBytesAsync(ct);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            // A failed measurement is never treated as zero — that would read as "cache is empty"
            // and could falsely re-arm a real crossing. Skip the tick with no state change; the
            // next scheduled tick retries.
            _logger.LogWarning(ex,
                "Cache-size alert check skipped — could not measure the cache tier size this tick.");
            return;
        }

        long warnBytes = InstanceSettingDefaults.ParseCacheSizeWarnBytes(
            await _orgs.GetInstanceSettingAsync(WarnBytesSettingKey, ct));

        var now = _time.GetUtcNow();
        await _orgs.SetInstanceSettingAsync(LastBytesSettingKey, cacheBytes.ToString(CultureInfo.InvariantCulture), ct);
        await _orgs.SetInstanceSettingAsync(LastMeasuredAtSettingKey, now.ToUtcIso(), ct);

        bool crossed = warnBytes > 0 && cacheBytes >= warnBytes;
        bool previouslyCrossed = await ReadCrossedStateAsync(ct);

        if (crossed == previouslyCrossed)
        {
            // No transition: either still under threshold (nothing to do) or still over it
            // (already alerted for this crossing — a repeat pass over the same state must stay
            // silent, which is what makes the alert "once per crossing" rather than "once per
            // tick while over").
            _logger.LogDebug(
                "Cache-size check: no state transition ({CacheBytes}B, threshold {WarnBytes}B, crossed={Crossed}).",
                cacheBytes, warnBytes, crossed);
            return;
        }

        if (!crossed)
        {
            await _orgs.SetInstanceSettingAsync(CrossedStateSettingKey, "0", ct);
            _logger.LogInformation(
                "Instance-wide proxy cache is back under its configured threshold ({CacheBytes}B < {WarnBytes}B). Re-armed.",
                cacheBytes, warnBytes);
            return;
        }

        string detail = System.Text.Json.JsonSerializer.Serialize(new
        {
            cache_bytes = cacheBytes,
            warn_bytes = warnBytes,
        }, Dependably.Infrastructure.Audit.Events.EventJsonOptions.Detail);

        // audit-attribution-ok: scheduled cache-size sweep — runs off a background timer with no
        // inbound request, so there is no actor or source IP to record.
        await _audit.LogSystemAsync(
            action: "system.cache_size_threshold_exceeded",
            detail: detail,
            ct: ct);

        _systemEvents.Notify(new SystemEventRecord("system.cache_size_threshold_exceeded", null, null, null));

        // Persisted only after the audit row and the notification both succeed: if either throws,
        // the flag is left exactly where it was (not crossed) so the next tick retries the whole
        // alert rather than silently deciding it already happened. A retried tick may duplicate an
        // alert that actually landed; that is the accepted cost of never losing one outright.
        await _orgs.SetInstanceSettingAsync(CrossedStateSettingKey, "1", ct);

        _logger.LogWarning(
            "Instance-wide proxy cache exceeded its configured threshold: {CacheBytes}B >= {WarnBytes}B.",
            cacheBytes, warnBytes);
    }

    private async Task<long> MeasureCacheBytesAsync(CancellationToken ct)
    {
        long cacheArtifactBytes = await _cacheArtifacts.GetTotalSizeBytesAsync(ct);
        long ociProxyOnlyBytes = await _cacheArtifacts.GetOciProxyOnlyDistinctDigestBytesAsync(ct);
        return cacheArtifactBytes + ociProxyOnlyBytes;
    }

    private async Task<bool> ReadCrossedStateAsync(CancellationToken ct)
        => await _orgs.GetInstanceSettingAsync(CrossedStateSettingKey, ct) == "1";
}
