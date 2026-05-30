using System.Security.Cryptography;
using System.Text;

namespace Dependably.Security;

/// <summary>
/// Partition-key derivation for the download / push rate limiters (#96).
///
/// Bucketing strategy: per-token-hash when an Authorization header is present so a single
/// misbehaving CI client can't DoS the writer queue, falling back to client IP so anonymous
/// fetches still get a sane cap. The token hash is truncated to a 12-character prefix so
/// metric labels (e.g. <c>dependably_rate_limit_rejected_total{token_hash_prefix=...}</c>)
/// stay low-cardinality without leaking the full SHA-256.
/// </summary>
public static class RateLimitPartitions
{
    /// <summary>
    /// Returns a partition key for the request: either <c>token:HHHHHHHHHHHH</c> (first 12
    /// hex chars of the SHA-256 of the bearer/basic credential) or <c>ip:1.2.3.4</c>.
    /// Falls back to the string <c>unknown</c> when neither is available — bundling all
    /// such requests into one bucket keeps it from becoming the noisy-neighbor vector
    /// the per-token bucket prevents.
    /// </summary>
    public static string GetPartitionKey(HttpContext httpContext)
    {
        var raw = ExtractRawTokenIfAny(httpContext);
        if (raw is not null)
        {
            var hashBytes = SHA256.HashData(Encoding.UTF8.GetBytes(raw));
            // 12 hex chars = 48 bits — collision-resistant enough for partitioning while
            // staying short in metric labels.
            return "token:" + Convert.ToHexString(hashBytes, 0, 6).ToLowerInvariant();
        }

        var ip = httpContext.GetNormalizedRemoteIp();
        if (!string.IsNullOrWhiteSpace(ip)) return "ip:" + ip;

        return "unknown";
    }

    /// <summary>
    /// Public so the OnRejected metric can read the partition key without re-computing.
    /// Returns just the "token:HHHH" or "ip:..." prefix-and-key.
    /// </summary>
    public static string GetMetricLabel(HttpContext httpContext) => GetPartitionKey(httpContext);

    private static string? ExtractRawTokenIfAny(HttpContext ctx)
    {
        var auth = ctx.Request.Headers.Authorization.FirstOrDefault();
        if (string.IsNullOrEmpty(auth)) return null;

        if (auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            return auth["Bearer ".Length..].Trim();

        if (auth.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                var encoded = auth["Basic ".Length..].Trim();
                var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(encoded));
                var colon = decoded.IndexOf(':');
                return colon >= 0 ? decoded[(colon + 1)..] : null;
            }
            catch
            {
                return null;
            }
        }

        return null;
    }
}
