using Microsoft.AspNetCore.Http.Features;
using Dependably.Infrastructure;
using Dependably.Protocol;

namespace Dependably.Security;

/// <summary>
/// Must be registered first in the middleware pipeline (before routing).
/// Resolves the org from the URL path and sets IHttpMaxRequestBodySizeFeature
/// to the effective per-org, per-ecosystem upload limit before the request body is read.
/// Returns 413 Problem Details if the request declares a Content-Length that already exceeds the limit.
/// </summary>
public sealed class UploadSizeLimitMiddleware
{
    private readonly RequestDelegate _next;

    public UploadSizeLimitMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(
        HttpContext ctx,
        OrgRepository orgs,
        IUploadLimitResolver limitResolver)
    {
        if (ctx.Request.Method is "POST" or "PUT" && await TryApplyLimitAsync(ctx, orgs, limitResolver))
            return;

        await _next(ctx);
    }

    // Returns true if the request was short-circuited with 413; false otherwise.
    private static async Task<bool> TryApplyLimitAsync(HttpContext ctx, OrgRepository orgs, IUploadLimitResolver limitResolver)
    {
        var (orgId, ecosystem) = await ResolveOrgAndEcosystemAsync(ctx, orgs);
        if (orgId is null || ecosystem is null) return false;

        var limit = await limitResolver.ResolveAsync(orgId, ecosystem, ctx.RequestAborted);
        if (limit is null) return false;

        if (ctx.Request.ContentLength > limit)
        {
            await Reject413Async(ctx, ecosystem, limit.Value);
            return true;
        }

        var bodySizeFeature = ctx.Features.Get<IHttpMaxRequestBodySizeFeature>();
        if (bodySizeFeature is not null && !bodySizeFeature.IsReadOnly)
            bodySizeFeature.MaxRequestBodySize = limit;
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

    private static async Task<(string? OrgId, string? Ecosystem)> ResolveOrgAndEcosystemAsync(
        HttpContext ctx, OrgRepository orgs)
    {
        // Matches /o/{orgSlug}/...
        var path = ctx.Request.Path.Value ?? string.Empty;
        var segments = path.TrimStart('/').Split('/', 3);
        if (segments.Length < 3 || segments[0] != "o")
            return (null, null);

        var slug = segments[1];
        var rest = segments[2];

        var ecosystem = rest switch
        {
            var s when s.StartsWith("simple/", StringComparison.OrdinalIgnoreCase) => "pypi",
            var s when s.StartsWith("npm/", StringComparison.OrdinalIgnoreCase) => "npm",
            var s when s.StartsWith("nuget/", StringComparison.OrdinalIgnoreCase) => "nuget",
            _ => null
        };

        if (ecosystem is null)
            return (null, null);

        var org = await orgs.GetBySlugAsync(slug, ct: ctx.RequestAborted);
        return (org?.Id, ecosystem);
    }
}
