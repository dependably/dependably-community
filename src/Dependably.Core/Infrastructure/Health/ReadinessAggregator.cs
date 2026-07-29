using Dapper;
using Dependably.Storage;

namespace Dependably.Infrastructure.Health;

/// <summary>
/// Shared readiness logic used by both GET /ready and HealthcheckPinger.
/// Returns a <see cref="ReadinessReport"/> carrying, per dependency, whether the check passed,
/// whether that dependency is required (see <see cref="ReadinessOptions"/>), and — for
/// server-side consumers (logs, structured pinger payloads) — the raw error text. The anonymous
/// /ready response reduces each check to ok/error and never exposes that text.
/// Each failed check is also logged here with full exception detail so both callers
/// get the same operator-facing diagnostics.
///
/// The blob-store probe result is cached for <see cref="ReadinessOptions.BlobProbeTtl"/> on the
/// injected <see cref="TimeProvider"/>. Readiness is polled by every load-balancer node against
/// every replica, and an object-store metadata call per poll is an unbudgeted permanent load
/// floor; a short TTL collapses a poll burst into one request without meaningfully delaying
/// detection. The metadata-store probe is never cached — it is the required dependency and must
/// reflect live state.
/// </summary>
public sealed class ReadinessAggregator
{
    private readonly IMetadataStore _db;
    private readonly IBlobStore _blobs;
    private readonly IRedisHealthProbe? _redis;
    private readonly ILogger<ReadinessAggregator> _logger;
    private readonly TimeProvider _time;
    private BlobProbeResult? _cachedBlobProbe;

    public ReadinessAggregator(
        IMetadataStore db,
        IBlobStore blobs,
        IServiceProvider sp,
        ILogger<ReadinessAggregator>? logger = null,
        TimeProvider? time = null,
        ReadinessOptions? options = null)
    {
        _db = db;
        _blobs = blobs;
        _redis = sp.GetService<IRedisHealthProbe>();
        _logger = logger
            ?? Microsoft.Extensions.Logging.Abstractions.NullLogger<ReadinessAggregator>.Instance;
        _time = time ?? sp.GetService<TimeProvider>() ?? TimeProvider.System;
        Options = options
            ?? sp.GetService<ReadinessOptions>()
            ?? ReadinessOptions.Resolve(sp.GetService<IConfiguration>());
    }

    /// <summary>Effective classification and probe-cost policy in force for this aggregator.</summary>
    public ReadinessOptions Options { get; }

    public async Task<ReadinessReport> CheckAsync(CancellationToken ct)
    {
        var checks = new List<ReadinessCheck>
        {
            Build(ReadinessOptions.DbCheck, await ProbeDbAsync(ct)),
            Build(ReadinessOptions.BlobStoreCheck, await ProbeBlobStoreAsync(ct)),
        };

        if (_redis is not null)
        {
            checks.Add(Build(ReadinessOptions.RedisCheck, await ProbeRedisAsync(ct)));
        }

        return new ReadinessReport(checks);
    }

    private ReadinessCheck Build(string name, string? error) =>
        new(name, Options.IsRequired(name), error);

    private async Task<string?> ProbeDbAsync(CancellationToken ct)
    {
        try
        {
            await using var conn = await _db.OpenAsync(ct);
            await conn.ExecuteScalarAsync<int>("SELECT 1", commandTimeout: 3);
            return null;
        }
        catch (Exception ex)
        {
            LogCheckFailure(ReadinessOptions.DbCheck, ex);
            return ex.Message;
        }
    }

    // Reuses the previous outcome — success or failure — while it is within the configured TTL,
    // so a poll burst across load-balancer nodes costs one object-store metadata call rather than
    // one per poll. Failures are cached too: a store that is 5xx-ing does not need to be probed
    // once per poll to stay reported as degraded.
    private async Task<string?> ProbeBlobStoreAsync(CancellationToken ct)
    {
        var now = _time.GetUtcNow();
        var cached = Volatile.Read(ref _cachedBlobProbe);
        if (Options.BlobProbeTtl > TimeSpan.Zero
            && cached is not null
            && now - cached.ProbedAt < Options.BlobProbeTtl)
        {
            return cached.Error;
        }

        string? error;
        try
        {
            // The cheapest call the abstraction offers: local backends stat a path and the
            // object-store backends issue a HEAD-equivalent metadata request, never an object read.
            // blobkey-ok: fixed liveness sentinel, not a namespaced artifact key.
            await _blobs.ExistsAsync("__ready_probe__", ct);
            error = null;
        }
        catch (Exception ex)
        {
            LogCheckFailure(ReadinessOptions.BlobStoreCheck, ex);
            error = ex.Message;
        }

        Volatile.Write(ref _cachedBlobProbe, new BlobProbeResult(now, error));
        return error;
    }

    private async Task<string?> ProbeRedisAsync(CancellationToken ct)
    {
        try
        {
            await _redis!.PingAsync(ct);
            return null;
        }
        catch (Exception ex)
        {
            LogCheckFailure(ReadinessOptions.RedisCheck, ex);
            return ex.Message;
        }
    }

    private void LogCheckFailure(string check, Exception ex) =>
        _logger.LogWarning(ex,
            "Readiness check failed: {Check} ({ExceptionType})",
            check, ex.GetType().Name);

    private sealed record BlobProbeResult(DateTimeOffset ProbedAt, string? Error);
}

/// <summary>
/// One dependency's readiness outcome. <paramref name="Required"/> reflects the
/// <see cref="ReadinessOptions"/> classification: a failed required check makes the replica
/// unready, a failed non-required check is reported as degradation only.
/// <paramref name="Error"/> is server-side detail and is never returned to anonymous callers.
/// </summary>
public sealed record ReadinessCheck(string Name, bool Required, string? Error)
{
    /// <summary>True when the probe succeeded.</summary>
    public bool Ok => Error is null;
}

/// <summary>
/// The full set of readiness outcomes for one aggregation pass.
/// </summary>
public sealed class ReadinessReport
{
    public ReadinessReport(IReadOnlyList<ReadinessCheck> checks) => Checks = checks;

    /// <summary>Every probed dependency, in probe order.</summary>
    public IReadOnlyList<ReadinessCheck> Checks { get; }

    /// <summary>True when every dependency passed — the strict view.</summary>
    public bool AllOk => Checks.All(c => c.Ok);

    /// <summary>True when every <em>required</em> dependency passed — the load-balancer view.</summary>
    public bool RequiredOk => Checks.All(c => !c.Required || c.Ok);

    /// <summary>Names of the dependencies whose probe failed.</summary>
    public IReadOnlyList<string> FailingChecks =>
        Checks.Where(c => !c.Ok).Select(c => c.Name).ToArray();

    /// <summary>Names of the dependencies classified as required.</summary>
    public IReadOnlyList<string> RequiredChecks =>
        Checks.Where(c => c.Required).Select(c => c.Name).ToArray();

    /// <summary>Per-check <c>ok</c>/<c>error</c> map, safe to return to anonymous callers.</summary>
    public Dictionary<string, string> ToStatusMap() =>
        Checks.ToDictionary(c => c.Name, c => c.Ok ? "ok" : "error", StringComparer.Ordinal);
}
