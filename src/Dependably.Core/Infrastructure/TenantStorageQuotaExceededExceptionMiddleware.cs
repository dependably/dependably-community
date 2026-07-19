using System.Text.Json;
using Dependably.Protocol;

namespace Dependably.Infrastructure;

/// <summary>
/// Translates <see cref="TenantStorageQuotaExceededException"/> raised by <c>UpstreamClient</c>
/// into a well-formed <c>413 Payload Too Large</c> response — the same status hosted publish
/// already returns for <c>tenant_quota_exceeded</c>. The body is RFC 7807-style problem JSON so
/// package manager clients display a clear message rather than a generic server error.
///
/// <para>Operators should raise the tenant's storage quota (Settings → Limits) or the
/// instance-level <c>default_storage_quota_bytes</c>, or the tenant should free space by
/// evicting cached proxy artifacts or unpublishing hosted versions.</para>
/// </summary>
public sealed class TenantStorageQuotaExceededExceptionMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<TenantStorageQuotaExceededExceptionMiddleware> _logger;

    public TenantStorageQuotaExceededExceptionMiddleware(
        RequestDelegate next,
        ILogger<TenantStorageQuotaExceededExceptionMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await _next(context);
        }
        catch (TenantStorageQuotaExceededException ex)
        {
            if (context.Response.HasStarted)
            {
                throw;
            }

            _logger.LogWarning(
                "Proxy cache fill rejected: org {OrgId} storage quota ({QuotaBytes} bytes) would be exceeded",
                ex.OrgId,
                ex.QuotaBytes);

            context.Response.Clear();
            context.Response.StatusCode = StatusCodes.Status413PayloadTooLarge;
            context.Response.ContentType = "application/problem+json";

            string payload = JsonSerializer.Serialize(new
            {
                type = "about:blank",
                title = "Tenant storage quota exceeded",
                status = 413,
                detail = "This tenant's storage quota would be exceeded by caching this proxied artifact. " +
                         "Raise the storage quota or free space by evicting cached artifacts or unpublishing versions.",
            });
            await context.Response.WriteAsync(payload);
        }
    }
}
