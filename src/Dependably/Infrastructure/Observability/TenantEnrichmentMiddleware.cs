using System.Diagnostics;
using Serilog.Context;

namespace Dependably.Infrastructure.Observability;

/// <summary>
/// Per-request log-context enricher. Pushes tenant identity (resolved by
/// <see cref="SubdomainTenantMiddleware"/>) plus request and trace
/// correlation IDs into <see cref="LogContext"/> so every log record emitted
/// during the request — including <c>UseSerilogRequestLogging</c>'s
/// completion summary — carries them.
///
/// Canonical property names are defined in
/// <c>dependably-enterprise/docs/observability/taxonomy.md</c>.
/// </summary>
public sealed class TenantEnrichmentMiddleware
{
    private readonly RequestDelegate _next;

    public TenantEnrichmentMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var pushes = new List<IDisposable>(6);
        try
        {
            pushes.Add(LogContext.PushProperty("RequestId", context.TraceIdentifier));

            var activity = Activity.Current;
            if (activity is not null)
            {
                pushes.Add(LogContext.PushProperty("TraceId", activity.TraceId.ToString()));
                pushes.Add(LogContext.PushProperty("SpanId", activity.SpanId.ToString()));
            }

            if (context.Items[TenantContext.HttpItemsKey] is TenantContext tenant
                && tenant.IsTenant
                && tenant.TenantId is { } tenantId)
            {
                pushes.Add(LogContext.PushProperty("TenantId", tenantId));
                pushes.Add(LogContext.PushProperty("OrgId", tenantId));
                if (tenant.TenantSlug is { } slug)
                {
                    pushes.Add(LogContext.PushProperty("TenantSlug", slug));
                }
            }

            await _next(context);
        }
        finally
        {
            for (int i = pushes.Count - 1; i >= 0; i--)
            {
                pushes[i].Dispose();
            }
        }
    }
}
