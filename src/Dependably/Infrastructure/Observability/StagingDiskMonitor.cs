namespace Dependably.Infrastructure.Observability;

/// <summary>
/// Polls the staging volume for disk-space metrics and logs a Serilog warning when
/// available space drops below the configured threshold.
///
/// <para>Metrics (sampled every 60 s by default; no per-tenant labels):</para>
/// <list type="bullet">
///   <item><c>dependably.staging.disk.available_bytes</c> — available bytes on the staging volume</item>
///   <item><c>dependably.staging.disk.used_bytes</c> — bytes used by files in the staging directory</item>
/// </list>
///
/// <para>Threshold: <c>STAGING_DISK_WARN_THRESHOLD_PERCENT</c> (default 10). When
/// available space falls below this fraction of the total volume size, a Warning is
/// logged. Errors during polling are logged and swallowed so the monitor never crashes
/// the host.</para>
/// </summary>
public sealed class StagingDiskMonitor : BackgroundService
{
    private readonly IStagingDiskInfo _diskInfo;
    private readonly double _warnThresholdFraction;
    private readonly TimeSpan _interval;
    private readonly ILogger<StagingDiskMonitor> _logger;

    public StagingDiskMonitor(
        IStagingDiskInfo diskInfo,
        IConfiguration config,
        ILogger<StagingDiskMonitor> logger)
    {
        _diskInfo = diskInfo;
        _logger = logger;

        int intervalSeconds = int.TryParse(
            config["STAGING_DISK_POLL_INTERVAL_SECONDS"], out int s) && s > 0 ? s : 60;
        _interval = TimeSpan.FromSeconds(intervalSeconds);

        int warnPercent = int.TryParse(
            config["STAGING_DISK_WARN_THRESHOLD_PERCENT"], out int p) && p is >= 0 and <= 100
            ? p
            : 10;
        _warnThresholdFraction = warnPercent / 100.0;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Brief startup delay so the gauge is not empty on cold launch.
        try { await Task.Delay(TimeSpan.FromSeconds(15), stoppingToken); }
        catch (OperationCanceledException) { return; }

        while (!stoppingToken.IsCancellationRequested)
        {
            PollOnce();

            try { await Task.Delay(_interval, stoppingToken); }
            catch (OperationCanceledException) { break; }
        }
    }

    internal void PollOnce()
    {
        try
        {
            long available = _diskInfo.GetAvailableBytes();
            long total = _diskInfo.GetTotalBytes();
            long used = _diskInfo.GetStagingDirectoryUsedBytes();

            DependablyMeter.RecordStagingDiskAvailable(available);
            DependablyMeter.RecordStagingDiskUsed(used);

            if (total > 0 && _warnThresholdFraction > 0)
            {
                double availableFraction = (double)available / total;
                if (availableFraction < _warnThresholdFraction)
                {
                    _logger.LogWarning(
                        "Staging volume free space is low: {AvailableBytes} bytes available of {TotalBytes} " +
                        "({AvailablePercent:F1}% free, threshold {ThresholdPercent:F1}%). " +
                        "Point PROXY_STAGING_PATH at a disk-backed volume with more capacity.",
                        available,
                        total,
                        availableFraction * 100,
                        _warnThresholdFraction * 100);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "StagingDiskMonitor: failed to poll staging volume disk space: {ExceptionType}",
                ex.GetType().Name);
        }
    }
}
