using System.Diagnostics;
using System.Net;
using System.Text.Json;
using Dependably.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Serilog;

namespace Dependably.Security;

/// <summary>
/// Gates <c>GET /metrics</c> per the resolved <see cref="MetricsAccessConfig"/>:
///   * effectively-disabled → 404 (endpoint vanishes)
///   * caller IP not in allowlist → 403 + one audit row per (scope, orgId, ip) per 10-min window
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
///
/// <para><see cref="AuditRepository"/> is resolved per-request via
/// <c>ctx.RequestServices</c> because this middleware is a singleton and
/// the repository carries a scoped DB connection.</para>
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
            await WriteScrapeDeniedAuditAsync(ctx, remote, "/metrics");
            ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
            await ctx.Response.WriteAsync("Forbidden");
            return;
        }

        _diagnostics.Record(remote, ScrapeDiagnostics.Outcome.Allowed);
        await _next(ctx);
    }

    /// <summary>
    /// Writes at most one audit row per (scope, orgId, ip, endpoint) per 10-minute cooldown
    /// window. Failures are logged as a Serilog Warning and do not propagate — the 403 response
    /// is always sent regardless of audit success.
    /// </summary>
    internal static async Task WriteScrapeDeniedAuditAsync(
        HttpContext ctx,
        IPAddress? remote,
        string endpoint,
        ScrapeDiagnostics diagnostics)
    {
        string sourceIp = IpAddressExtensions.Normalize(remote) ?? "unknown";

        // Derive scope and orgId from the TenantContext stashed by SubdomainTenantMiddleware,
        // which runs before this middleware in the pipeline.
        var tenantCtx = ctx.Items[TenantContext.HttpItemsKey] as TenantContext;
        string scope = (tenantCtx is { IsTenant: true }) ? "tenant" : "system";
        string? orgId = (tenantCtx is { IsTenant: true }) ? tenantCtx.TenantId : null;

        if (!diagnostics.ShouldAudit(scope, orgId, sourceIp, endpoint))
        {
            return;
        }

        try
        {
            var audit = ctx.RequestServices.GetService<AuditRepository>();
            if (audit is null)
            {
                return;
            }

            string detail = JsonSerializer.Serialize(new { endpoint, reason = "denied_ip" });

            if (scope == "tenant" && orgId is not null)
            {
                await audit.LogAsync(
                    action: "metrics.scrape_denied",
                    orgId: orgId,
                    sourceIp: sourceIp,
                    detail: detail,
                    ct: ctx.RequestAborted);
            }
            else
            {
                await audit.LogSystemAsync(
                    action: "metrics.scrape_denied",
                    sourceIp: sourceIp,
                    detail: detail,
                    ct: ctx.RequestAborted);
            }
        }
        catch (Exception ex)
        {
            Log.Warning(ex,
                "{ExceptionType} writing metrics scrape-denied audit for {SourceIp} on {Endpoint}. TraceId={TraceId}",
                ex.GetType().Name,
                sourceIp,
                endpoint,
                Activity.Current?.TraceId.ToString());
        }
    }

    private Task WriteScrapeDeniedAuditAsync(HttpContext ctx, IPAddress? remote, string endpoint)
        => WriteScrapeDeniedAuditAsync(ctx, remote, endpoint, _diagnostics);

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
