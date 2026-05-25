using System.Diagnostics;
using OpenTelemetry;

namespace Dependably.Infrastructure.Observability;

/// <summary>
/// OpenTelemetry processor that stamps <c>dependably.tenant_id</c> and
/// <c>dependably.org_id</c> on every span produced inside a tenant-scoped
/// HTTP request. Reads from <c>HttpContext.Items["TenantContext"]</c>
/// populated by <see cref="SubdomainTenantMiddleware"/>.
///
/// Hooks <see cref="OnEnd"/> rather than <see cref="OnStart"/> because the
/// ASP.NET Core auto-instrumentation creates the server activity before any
/// middleware runs — the tenant context is not yet resolved at OnStart.
///
/// Custom spans created via <see cref="DependablyActivitySource"/> can also
/// set the tags directly at the call site; this enricher exists to cover
/// the framework-emitted server spans that have no application-side hook.
/// </summary>
public sealed class TenantSpanEnricher : BaseProcessor<Activity>
{
    private readonly IHttpContextAccessor _http;

    public TenantSpanEnricher(IHttpContextAccessor http)
    {
        _http = http;
    }

    public override void OnEnd(Activity activity)
    {
        if (_http.HttpContext?.Items[TenantContext.HttpItemsKey] is TenantContext ctx
            && ctx.IsTenant
            && ctx.TenantId is { } tenantId)
        {
            activity.SetTag("dependably.tenant_id", tenantId);
            activity.SetTag("dependably.org_id", tenantId);
        }
    }
}
