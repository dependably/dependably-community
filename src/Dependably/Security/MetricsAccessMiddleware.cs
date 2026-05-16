using System.Net;
using NetTools;

namespace Dependably.Security;

/// <summary>
/// Restricts GET /metrics to localhost or IPs in METRICS_ALLOWED_IPS.
/// Returns 403 for all other callers (OWASP API8:2023).
/// </summary>
public sealed class MetricsAccessMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IReadOnlyList<IPAddressRange> _allowedRanges;

    public MetricsAccessMiddleware(RequestDelegate next, IConfiguration config)
    {
        _next = next;

        var configured = config["METRICS_ALLOWED_IPS"] ?? "127.0.0.1";
        _allowedRanges = configured
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(IPAddressRange.Parse)
            .ToList();
    }

    public async Task InvokeAsync(HttpContext ctx)
    {
        if (ctx.Request.Path.StartsWithSegments("/metrics"))
        {
            var remote = ctx.Connection.RemoteIpAddress;
            if (remote is null || !IsAllowed(remote))
            {
                ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
                await ctx.Response.WriteAsync("Forbidden");
                return;
            }
        }

        await _next(ctx);
    }

    private bool IsAllowed(IPAddress ip)
    {
        var mapped = ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip;
        // Range-check stays on the IPAddress object (not the string form) because
        // IPNetwork.Contains needs the parsed address.
        return _allowedRanges.Any(r => r.Contains(mapped));
    }
}
