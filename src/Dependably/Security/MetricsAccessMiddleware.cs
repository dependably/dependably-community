using System.Net;

namespace Dependably.Security;

/// <summary>
/// Gates <c>GET /metrics</c> per the resolved <see cref="MetricsAccessConfig"/>:
///   * effectively-disabled → 404 (endpoint vanishes)
///   * caller IP not in allowlist → 403
///   * otherwise → forward to the Prometheus exporter
///
/// Every request is recorded in <see cref="ScrapeDiagnostics"/> for the
/// sysadmin observability page.
///
/// <para>The caller IP comes from <c>Connection.RemoteIpAddress</c>,
/// which is the value <i>after</i> <c>ForwardedHeadersMiddleware</c>
/// rewrites it from <c>X-Forwarded-For</c> per the existing
/// <c>Program.cs</c> config. Operators behind a reverse proxy must keep
/// the proxy in <c>KnownProxies</c> / <c>KnownNetworks</c> for the
/// allowlist to match the original client IP. See
/// <c>dependably-enterprise/docs/reverse-proxy.md</c>.</para>
/// </summary>
public sealed class MetricsAccessMiddleware
{
    private readonly RequestDelegate _next;
    private readonly MetricsAccessConfig _config;
    private readonly ScrapeDiagnostics _diagnostics;

    public MetricsAccessMiddleware(
        RequestDelegate next,
        MetricsAccessConfig config,
        ScrapeDiagnostics diagnostics)
    {
        _next = next;
        _config = config;
        _diagnostics = diagnostics;
    }

    public async Task InvokeAsync(HttpContext ctx)
    {
        if (!ctx.Request.Path.StartsWithSegments("/metrics"))
        {
            await _next(ctx);
            return;
        }

        var resolved = await _config.ResolveAsync(ctx.RequestAborted);
        var remote = ctx.Connection.RemoteIpAddress;

        if (!resolved.Enabled)
        {
            _diagnostics.Record(remote, ScrapeDiagnostics.Outcome.DeniedDisabled);
            ctx.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }

        if (remote is null || !IsIpAllowed(remote, resolved.Allowed))
        {
            _diagnostics.Record(remote, ScrapeDiagnostics.Outcome.DeniedIp);
            ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
            await ctx.Response.WriteAsync("Forbidden");
            return;
        }

        _diagnostics.Record(remote, ScrapeDiagnostics.Outcome.Allowed);
        await _next(ctx);
    }

    /// <summary>
    /// Allowlist membership check shared with the <c>/version</c> endpoint, which gates
    /// on the same resolved metrics allowlist. IPv4-mapped IPv6 addresses (dual-stack
    /// sockets) are collapsed to dotted-quad before matching.
    /// </summary>
    internal static bool IsIpAllowed(IPAddress ip, IReadOnlyList<NetTools.IPAddressRange> allowed)
    {
        var mapped = ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip;
        return allowed.Any(range => range.Contains(mapped));
    }
}
