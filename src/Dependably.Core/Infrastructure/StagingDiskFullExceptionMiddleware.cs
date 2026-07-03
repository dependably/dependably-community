using System.Text.Json;
using Dependably.Protocol;

namespace Dependably.Infrastructure;

/// <summary>
/// Translates <see cref="StagingDiskFullException"/> raised by <c>UpstreamClient</c>
/// into a well-formed <c>507 Insufficient Storage</c> response. The body is
/// RFC 7807-style problem JSON so package manager clients display a clear message
/// rather than a generic server error. Disk metrics are logged server-side only —
/// they are not included in the response body to avoid leaking volume layout details.
///
/// <para>Operators should free space on the staging volume, increase
/// <c>STAGING_DISK_FLOOR_BYTES</c>, or point <c>PROXY_STAGING_PATH</c> at a volume
/// with more capacity.</para>
/// </summary>
public sealed class StagingDiskFullExceptionMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<StagingDiskFullExceptionMiddleware> _logger;

    public StagingDiskFullExceptionMiddleware(
        RequestDelegate next,
        ILogger<StagingDiskFullExceptionMiddleware> logger)
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
        catch (StagingDiskFullException ex)
        {
            if (context.Response.HasStarted)
            {
                throw;
            }

            _logger.LogWarning(
                "Proxy fetch rejected: staging disk space {AvailableBytes} below floor {FloorBytes}",
                ex.AvailableBytes,
                ex.FloorBytes);

            context.Response.Clear();
            context.Response.StatusCode = StatusCodes.Status507InsufficientStorage;
            context.Response.ContentType = "application/problem+json";

            string payload = JsonSerializer.Serialize(new
            {
                type = "about:blank",
                title = "Insufficient storage",
                status = 507,
                detail = "The staging volume does not have enough free space to accept a new proxy fetch. " +
                         "Free space on the staging volume or increase STAGING_DISK_FLOOR_BYTES.",
            });
            await context.Response.WriteAsync(payload);
        }
    }
}
