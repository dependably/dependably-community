using Dapper;
using Dependably.Infrastructure.Redis;
using Dependably.Storage;

namespace Dependably.Infrastructure.Health;

/// <summary>
/// Shared readiness logic used by both GET /ready and HealthcheckPinger.
/// Returns a dictionary of check name → error message (null means ok).
/// </summary>
public sealed class ReadinessAggregator
{
    private readonly IMetadataStore _db;
    private readonly IBlobStore _blobs;
    private readonly IRedisClient? _redis;

    public ReadinessAggregator(IMetadataStore db, IBlobStore blobs, IServiceProvider sp)
    {
        _db = db;
        _blobs = blobs;
        _redis = sp.GetService<IRedisClient>();
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
        catch (Exception ex) { result["db"] = ex.Message; }

        try
        {
            await _blobs.ExistsAsync("__ready_probe__", ct);
            result["blob_store"] = null;
        }
        catch (Exception ex) { result["blob_store"] = ex.Message; }

        if (_redis is not null)
        {
            try
            {
                await _redis.GetDatabase().PingAsync();
                result["redis"] = null;
            }
            catch (Exception ex) { result["redis"] = ex.Message; }
        }

        return result;
    }
}
