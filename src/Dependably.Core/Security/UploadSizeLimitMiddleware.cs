using Dependably.Infrastructure;
using Dependably.Protocol;
using Microsoft.AspNetCore.Http.Features;

namespace Dependably.Security;

/// <summary>
/// Registered after <see cref="SubdomainTenantMiddleware"/> (which resolves the tenant from the
/// host/subdomain into <c>HttpContext.Items["TenantContext"]</c>) and after
/// <see cref="Infrastructure.TransparentInterceptMiddleware"/> (which rewrites bare-host paths to
/// their ecosystem prefix), but before routing. Reads the resolved tenant, keys the ecosystem off
/// the host-relative path prefix (<c>/pypi</c>, <c>/npm</c>, <c>/nuget</c>, <c>/maven</c>,
/// <c>/rpm</c>, <c>/v2</c>), and sets <see cref="IHttpMaxRequestBodySizeFeature"/> to the
/// effective per-org, per-ecosystem upload limit before the request body is read.
/// Returns 413 Problem Details if the request declares a Content-Length that already exceeds
/// the limit — before any body bytes are buffered.
/// </summary>
public sealed class UploadSizeLimitMiddleware
{
    private readonly RequestDelegate _next;

    public UploadSizeLimitMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext ctx, IUploadLimitResolver limitResolver)
    {
        // PATCH is included for OCI chunked blob uploads (/v2/.../blobs/uploads/{id}).
        if (ctx.Request.Method is "POST" or "PUT" or "PATCH" && await TryApplyLimitAsync(ctx, limitResolver))
        {
            return;
        }

        await _next(ctx);
    }

    // Returns true if the request was short-circuited with 413; false otherwise.
    private static async Task<bool> TryApplyLimitAsync(HttpContext ctx, IUploadLimitResolver limitResolver)
    {
        var (orgId, ecosystem) = ResolveOrgAndEcosystem(ctx);
        if (orgId is null || ecosystem is null)
        {
            return false;
        }

        long? limit = await limitResolver.ResolveAsync(orgId, ecosystem, ctx.RequestAborted);
        if (limit is null)
        {
            return false;
        }

        if (ctx.Request.ContentLength > limit)
        {
            await Reject413Async(ctx, ecosystem, limit.Value);
            return true;
        }

        var bodySizeFeature = ctx.Features.Get<IHttpMaxRequestBodySizeFeature>();
        if (bodySizeFeature is not null && !bodySizeFeature.IsReadOnly)
        {
            bodySizeFeature.MaxRequestBodySize = limit;
        }

        return false;
    }

    private static async Task Reject413Async(HttpContext ctx, string ecosystem, long limit)
    {
        ctx.Response.StatusCode = StatusCodes.Status413RequestEntityTooLarge;
        ctx.Response.ContentType = "application/problem+json";
        await ctx.Response.WriteAsync(
            $"{{\"type\":\"about:blank\",\"title\":\"Payload Too Large\",\"status\":413," +
            $"\"detail\":\"Upload exceeds the {ecosystem} limit of {limit} bytes.\"}}",
            ctx.RequestAborted);
    }

    private static (string? OrgId, string? Ecosystem) ResolveOrgAndEcosystem(HttpContext ctx)
    {
        // Tenant identity comes from SubdomainTenantMiddleware, which has already run and
        // stashed the resolved TenantContext. Apex / uninitialized requests have no tenant
        // and therefore no per-tenant limit (those surfaces carry no protocol uploads).
        if (ctx.Items.TryGetValue(TenantContext.HttpItemsKey, out object? item)
            && item is TenantContext { IsTenant: true, TenantId: { } orgId })
        {
            return (orgId, EcosystemForPath(ctx.Request.Path.Value ?? string.Empty));
        }

        return (null, null);
    }

    // Protocol routes are host-relative (tenancy is host-resolved, not path-resolved), so the
    // ecosystem is keyed off the first path segment. TransparentInterceptMiddleware has already
    // prepended the prefix for bare-host (transparent intercept) deployments.
    private static string? EcosystemForPath(string path) => path switch
    {
        _ when StartsWithSegment(path, "/pypi") || StartsWithSegment(path, "/simple") => "pypi",
        _ when StartsWithSegment(path, "/npm") => "npm",
        _ when StartsWithSegment(path, "/nuget") => "nuget",
        _ when StartsWithSegment(path, "/maven") => "maven",
        _ when StartsWithSegment(path, "/rpm") => "rpm",
        // OCI Distribution Spec mandates /v2/ — the path differs from the ecosystem key.
        _ when StartsWithSegment(path, "/v2") => "oci",
        _ => null,
    };

    private static bool StartsWithSegment(string path, string prefix) =>
        path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
        && (path.Length == prefix.Length || path[prefix.Length] == '/');
}
