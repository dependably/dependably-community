using Dapper;
using Dependably.Infrastructure.Redis;
using Dependably.Storage;

namespace Dependably.Infrastructure.Health;

/// <summary>
/// Shared readiness logic used by both GET /ready and HealthcheckPinger.
/// Returns a dictionary of check name → error message (null means ok).
/// The error message is for server-side consumers (logs, structured pinger payloads);
/// the anonymous /ready response reduces it to ok/error and never exposes the text.
/// Each failed check is also logged here with full exception detail so both callers
/// get the same operator-facing diagnostics.
/// </summary>
public sealed class ReadinessAggregator
{
    private readonly IMetadataStore _db;
    private readonly IBlobStore _blobs;
    private readonly IRedisClient? _redis;
    private readonly ILogger<ReadinessAggregator> _logger;

    public ReadinessAggregator(
        IMetadataStore db,
        IBlobStore blobs,
        IServiceProvider sp,
        ILogger<ReadinessAggregator>? logger = null)
    {
        _db = db;
        _blobs = blobs;
        _redis = sp.GetService<IRedisClient>();
        _logger = logger
            ?? Microsoft.Extensions.Logging.Abstractions.NullLogger<ReadinessAggregator>.Instance;
    }

    public async Task<Dictionary<string, string?>> CheckAsync(CancellationToken ct)
    {
        var result = new Dictionary<string, string?>();

        try
        {
            await using var conn = await _db.OpenAsync(ct);
            await conn.ExecuteScalarAsync<int>("SELECT 1", commandTimeout: 3);
            result["db"] = null;
        }
        catch (Exception ex)
        {
            result["db"] = ex.Message;
            LogCheckFailure("db", ex);
        }

        try
        {
            // blobkey-ok: fixed liveness sentinel, not a namespaced artifact key.
            await _blobs.ExistsAsync("__ready_probe__", ct);
            result["blob_store"] = null;
        }
        catch (Exception ex)
        {
            result["blob_store"] = ex.Message;
            LogCheckFailure("blob_store", ex);
        }

        if (_redis is not null)
        {
            try
            {
                await _redis.GetDatabase().PingAsync();
                result["redis"] = null;
            }
            catch (Exception ex)
            {
                result["redis"] = ex.Message;
                LogCheckFailure("redis", ex);
            }
        }

        return result;
    }

    private void LogCheckFailure(string check, Exception ex) =>
        _logger.LogWarning(ex,
            "Readiness check failed: {Check} ({ExceptionType})",
            check, ex.GetType().Name);
}
