using Dependably.Storage;

namespace Dependably.Infrastructure;

/// <summary>
/// Translates <see cref="TenantNotReadyException"/> raised by
/// <see cref="ITenantStorageResolver.GetRegistryAsync"/> into structured HTTP responses via
/// <see cref="TenantNotReadyResponseWriter"/>. Without this, every gated path (publish, import)
/// returns 500 and clients can't tell "tenant doesn't exist" from "your bucket is still being
/// provisioned, retry shortly" from "this org is suspended".
///
/// <para>
/// <see cref="TenantStatusEnforcementMiddleware"/> raises the same
/// <see cref="TenantNotReadyReason.StatusInactive"/> refusal for a resolved non-active tenant, but
/// calls <see cref="TenantNotReadyResponseWriter"/> directly instead of throwing through this
/// middleware — see that writer's doc comment for why (an exception unwinding through
/// <c>UseSerilogRequestLogging</c> logs a spurious Error-level 500 for every refused request).
/// This middleware stays registered early regardless, because <c>GetRegistryAsync</c>'s throw is
/// the one case that genuinely has no other way back to the pipeline.
/// </para>
/// </summary>
public sealed class TenantNotReadyExceptionMiddleware
{
    private readonly RequestDelegate _next;

    public TenantNotReadyExceptionMiddleware(RequestDelegate next) => _next = next;

    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await _next(context);
        }
        catch (TenantNotReadyException ex)
        {
            if (context.Response.HasStarted)
            {
                throw;
            }

            await TenantNotReadyResponseWriter.WriteAsync(context, ex.Reason);
        }
    }
}
