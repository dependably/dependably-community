using System.Diagnostics;
using Dependably.Infrastructure.Observability;
using Dependably.Infrastructure.Redis;

namespace Dependably.Infrastructure.Health;

/// <summary>
/// Outbound healthcheck heartbeat. Pings a configured URL on an interval so
/// external monitors (Healthchecks.io, Better Uptime, Cronitor, etc.) can alert
/// when a replica is unreachable from the internet.
///
/// Silent when HEALTHCHECK_PING_URL is not set.
///
/// Environment variables:
///   HEALTHCHECK_PING_URL               — required to enable
///   HEALTHCHECK_PING_INTERVAL_SECONDS  — default 60
///   HEALTHCHECK_PING_TIMEOUT_SECONDS   — default 10
///   HEALTHCHECK_PING_METHOD            — GET (default) or POST
///   HEALTHCHECK_PING_PAYLOAD           — none (default) or status (forces POST with JSON body)
///   HEALTHCHECK_PING_INSTANCE_ID       — defaults to hostname; included in POST payload
///   HEALTHCHECK_PING_FAIL_URL          — optional; called when local readiness fails
///   HEALTHCHECK_PING_SCOPE             — replica (default) or leader
/// </summary>
public sealed class HealthcheckPinger : BackgroundService
{
    // Default interval and timeout values (seconds) when env-vars are not configured.
    private const int DefaultPingIntervalSeconds = 60;
    private const int DefaultPingTimeoutSeconds = 10;

    private readonly IHttpClientFactory _http;
    private readonly IDistributedLock _locks;
    private readonly ReadinessAggregator _readiness;
    private readonly IAirGapMode _airGap;
    private readonly ILogger<HealthcheckPinger> _logger;
    private readonly string? _pingUrl;
    private readonly string? _failUrl;
    private readonly TimeSpan _interval;
    private readonly TimeSpan _timeout;
    private readonly bool _usePost;
    private readonly bool _sendPayload;
    private readonly bool _leaderScope;
    private readonly string _instanceId;
    private readonly string _deploymentMode;
    private readonly TimeProvider _time;
    private readonly DateTimeOffset _startedAt;

    public HealthcheckPinger(
        IHttpClientFactory http,
        IDistributedLock locks,
        ReadinessAggregator readiness,
        IAirGapMode airGap,
        IConfiguration config,
        ILogger<HealthcheckPinger> logger,
        TimeProvider time)
    {
        _http = http;
        _locks = locks;
        _readiness = readiness;
        _airGap = airGap;
        _logger = logger;
        _time = time;
        _startedAt = time.GetUtcNow();

        _pingUrl = config["HEALTHCHECK_PING_URL"];
        _failUrl = config["HEALTHCHECK_PING_FAIL_URL"];
        _interval = TimeSpan.FromSeconds(
            int.TryParse(config["HEALTHCHECK_PING_INTERVAL_SECONDS"], out int i) ? i : DefaultPingIntervalSeconds);
        _timeout = TimeSpan.FromSeconds(
            int.TryParse(config["HEALTHCHECK_PING_TIMEOUT_SECONDS"], out int t) ? t : DefaultPingTimeoutSeconds);
        _usePost = string.Equals(config["HEALTHCHECK_PING_METHOD"], "POST", StringComparison.OrdinalIgnoreCase);
        _sendPayload = string.Equals(config["HEALTHCHECK_PING_PAYLOAD"], "status", StringComparison.OrdinalIgnoreCase);
        _leaderScope = string.Equals(config["HEALTHCHECK_PING_SCOPE"], "leader", StringComparison.OrdinalIgnoreCase);
        _instanceId = config["HEALTHCHECK_PING_INSTANCE_ID"] ?? Environment.MachineName;
        _deploymentMode = (config["DEPENDABLY_DEPLOYMENT_MODE"] ?? "standalone").ToLowerInvariant();
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (string.IsNullOrWhiteSpace(_pingUrl))
        {
            return; // Feature disabled — silent exit.
        }

        _logger.LogInformation(
            "HealthcheckPinger enabled: url={Url} interval={Interval}s scope={Scope}",
            _pingUrl, _interval.TotalSeconds, _leaderScope ? "leader" : "replica");

        while (!stoppingToken.IsCancellationRequested)
        {
            await Task.Delay(_interval, stoppingToken);
            await PingOnceAsync(stoppingToken);
        }
    }

    private async Task PingOnceAsync(CancellationToken ct)
    {
        // Air-gap gate: the heartbeat is an outbound request, so suppress it when the instance
        // is air-gapped (AIR_GAPPED) or this job is named in DISABLE_BACKGROUND_JOBS.
        if (_airGap.IsJobDisabled("healthcheck-pinger"))
        {
            return;
        }

        // In leader scope, only the elected leader pings.
        if (_leaderScope)
        {
            await using var handle = await _locks.TryAcquireAsync("healthcheck:leader-ping", _interval, ct);
            if (handle is null)
            {
                return;
            }
        }

        var checks = await _readiness.CheckAsync(ct);
        bool ready = checks.Values.All(v => v is null);

        string targetUrl = ready ? _pingUrl! : (_failUrl ?? _pingUrl!);
        var stopwatch = Stopwatch.StartNew();

        try
        {
            using var client = _http.CreateClient("healthcheck-pinger");
            client.Timeout = _timeout;

            using var resp = await SendPingAsync(client, targetUrl, ready, checks, ct);
            RecordPingResult(resp, targetUrl);
        }
        catch (Exception ex)
        {
            DependablyMeter.HealthcheckPings.Add(1, new KeyValuePair<string, object?>("outcome", "server_error"));
            _logger.LogWarning(ex, "HealthcheckPinger: transport failure pinging {Url}.", targetUrl);
        }
        finally
        {
            DependablyMeter.HealthcheckPingDuration.Record(stopwatch.Elapsed.TotalSeconds);
        }
    }

    // POSTs a JSON status payload when configured (HEALTHCHECK_USE_POST / payload mode), else
    // issues a lightweight GET. Caller owns disposal of the returned response.
    private async Task<HttpResponseMessage> SendPingAsync(
        HttpClient client, string targetUrl, bool ready, IReadOnlyDictionary<string, string?> checks, CancellationToken ct)
    {
        if (_usePost || _sendPayload)
        {
            long uptime = (long)(_time.GetUtcNow() - _startedAt).TotalSeconds;
            var body = new
            {
                instance_id = _instanceId,
                uptime_seconds = uptime,
                deployment_mode = _deploymentMode,
                status = ready ? "ready" : "degraded",
                checks = checks.ToDictionary(
                    kv => kv.Key,
                    kv => kv.Value is null ? "ok" : "error"),
            };
            return await client.PostAsJsonAsync(targetUrl, body, ct);
        }
        return await client.GetAsync(targetUrl, HttpCompletionOption.ResponseHeadersRead, ct);
    }

    private void RecordPingResult(HttpResponseMessage resp, string targetUrl)
    {
        if (resp.IsSuccessStatusCode)
        {
            DependablyMeter.HealthcheckPings.Add(1, new KeyValuePair<string, object?>("outcome", "success"));
            _logger.LogDebug("HealthcheckPinger: ping succeeded ({StatusCode}).", (int)resp.StatusCode);
        }
        else
        {
            DependablyMeter.HealthcheckPings.Add(1, new KeyValuePair<string, object?>("outcome", "server_error"));
            _logger.LogWarning(
                "HealthcheckPinger: ping returned non-2xx ({StatusCode}) from {Url}.",
                (int)resp.StatusCode, targetUrl);
        }
    }
}
