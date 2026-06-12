using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Dependably.Security;

/// <summary>
/// Partition-key derivation for the download / push rate limiters.
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
        string? raw = ExtractRawTokenIfAny(httpContext);
        if (raw is not null)
        {
            byte[] hashBytes = SHA256.HashData(Encoding.UTF8.GetBytes(raw));
            // 12 hex chars = 48 bits — collision-resistant enough for partitioning while
            // staying short in metric labels.
            return "token:" + Convert.ToHexString(hashBytes, 0, 6).ToLowerInvariant();
        }

        string? ip = httpContext.GetNormalizedRemoteIp();
        return !string.IsNullOrWhiteSpace(ip) ? "ip:" + ip : "unknown";
    }

    /// <summary>
    /// Partition-key derivation for the management API GlobalLimiter. Preference order:
    /// <list type="number">
    ///   <item><c>token:HHHHHHHHHHHH</c> — an API token in the Authorization header gives
    ///     each automation client its own bucket, independent of the originating IP.</item>
    ///   <item><c>user:{sub}</c> — a cookie-session SPA user is identified by the JWT
    ///     <c>sub</c> claim on <c>ctx.User</c> (populated by <c>UseAuthentication</c> before
    ///     the GlobalLimiter runs). Each tenant user gets a private budget; NAT'd offices
    ///     sharing one egress IP no longer collapse into a single bucket.</item>
    ///   <item><c>ip:1.2.3.4</c> — unauthenticated requests fall back to the remote IP.</item>
    ///   <item><c>unknown</c> — no Authorization header, no authenticated principal, and no
    ///     resolvable IP (in-process test probes).</item>
    /// </list>
    /// </summary>
    public static string GetManagementPartitionKey(HttpContext httpContext)
    {
        // API token in Authorization header — highest priority so CI automation clients
        // get their own per-token budget regardless of whether a session is also present.
        string? raw = ExtractRawTokenIfAny(httpContext);
        if (raw is not null)
        {
            byte[] hashBytes = SHA256.HashData(Encoding.UTF8.GetBytes(raw));
            return "token:" + Convert.ToHexString(hashBytes, 0, 6).ToLowerInvariant();
        }

        // Authenticated SPA session: UseAuthentication runs before the GlobalLimiter, so
        // ctx.User is populated. MapInboundClaims=false keeps the JWT "sub" as-is; the
        // NameIdentifier fallback covers any scheme that does map to the URI claim type.
        string? sub = httpContext.User.FindFirst("sub")?.Value
            ?? httpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (!string.IsNullOrEmpty(sub))
        {
            return "user:" + sub;
        }

        string? ip = httpContext.GetNormalizedRemoteIp();
        return !string.IsNullOrWhiteSpace(ip) ? "ip:" + ip : "unknown";
    }

    /// <summary>
    /// Public so the OnRejected metric can read the partition key without re-computing.
    /// Returns just the "token:HHHH" or "ip:..." prefix-and-key.
    /// </summary>
    public static string GetMetricLabel(HttpContext httpContext) => GetPartitionKey(httpContext);

    private static string? ExtractRawTokenIfAny(HttpContext ctx)
    {
        string? auth = ctx.Request.Headers.Authorization.FirstOrDefault();
        if (string.IsNullOrEmpty(auth))
        {
            return null;
        }

        if (auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            return auth["Bearer ".Length..].Trim();
        }

        if (auth.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                string encoded = auth["Basic ".Length..].Trim();
                string decoded = Encoding.UTF8.GetString(Convert.FromBase64String(encoded));
                int colon = decoded.IndexOf(':');
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
