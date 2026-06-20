using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Dependably.Security;

/// <summary>
/// Partition-key derivation for the download / push rate limiters.
///
/// Bucketing strategy: prefer the validated principal identity (<c>sub</c> claim from
/// <c>httpContext.User</c>, populated by <c>UseAuthentication</c> before the rate limiter
/// runs) so that each authenticated user gets a private, NAT-safe budget. Unauthenticated
/// requests fall back to the remote IP. Raw Authorization headers are never hashed:
/// an attacker sending unique forged headers has no validated <c>sub</c> claim, so all
/// such requests land in the same IP bucket — the per-principal unlimited-bucket attack
/// is closed without collapsing legitimate users behind the same NAT into one shared budget.
/// </summary>
public static class RateLimitPartitions
{
    // Number of SHA-256 bytes taken for the token partition key prefix (6 bytes = 12 hex chars).
    // Used by GetManagementPartitionKey, which partitions management-API traffic by raw
    // Authorization header (highest priority) then by validated sub claim, then by IP.
    private const int TokenHashPrefixBytes = 6;

    /// <summary>
    /// Returns a partition key for the request, in preference order:
    /// <list type="number">
    ///   <item><c>user:{sub}</c> — the validated principal's <c>sub</c> claim (populated by
    ///     <c>UseAuthentication</c> before the rate limiter runs). Each authenticated user
    ///     gets a private budget regardless of NAT; forged Authorization headers yield no
    ///     validated claim and therefore do not produce a fresh bucket.</item>
    ///   <item><c>ip:1.2.3.4</c> — unauthenticated requests fall back to the remote IP.</item>
    ///   <item><c>unknown</c> — no authenticated principal and no resolvable IP (in-process
    ///     test probes).</item>
    /// </list>
    /// Raw Authorization headers are intentionally ignored: a forged or invalid token fails
    /// authentication, so <c>httpContext.User</c> carries no <c>sub</c> claim and the request
    /// shares the IP bucket with every other unauthenticated probe from the same address.
    /// </summary>
    public static string GetPartitionKey(HttpContext httpContext)
    {
        // Validated principal: UseAuthentication runs before UseRateLimiter, so User is
        // already populated for any endpoint that opted in to an authentication scheme.
        // MapInboundClaims=false keeps the JWT "sub" as-is; NameIdentifier covers schemes
        // that map claims to the URI type.
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
            return "token:" + Convert.ToHexString(hashBytes, 0, TokenHashPrefixBytes).ToLowerInvariant();
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
