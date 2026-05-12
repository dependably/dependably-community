namespace Dependably.Infrastructure;

/// <summary>
/// Path rewriter for transparent-intercept deployments (#43). When <c>ROUTING_MODE=transparent</c>
/// and the inbound <c>Host</c> header matches a configured ecosystem hostname, prepends the
/// ecosystem prefix (<c>/npm</c>, <c>/pypi</c>, <c>/nuget</c>) to the request path so the
/// existing prefix-routed controllers serve the request unchanged.
///
/// Idempotent: if the path already starts with the prefix, no rewrite happens. Hosts not in
/// the map (the deployment hostname, the admin UI host) pass through.
///
/// Example: <c>Host: registry.npmjs.org</c> + <c>GET /lodash</c> → internally
/// <c>GET /npm/lodash</c>. The client sees nothing change; <see cref="IPublicUrlBuilder"/>
/// echoes back the inbound host on outbound metadata.
/// </summary>
public sealed class TransparentInterceptMiddleware
{
    private readonly RequestDelegate _next;
    private readonly HostEcosystemMap _map;

    public TransparentInterceptMiddleware(RequestDelegate next, HostEcosystemMap map)
    {
        _next = next;
        _map = map;
    }

    public Task InvokeAsync(HttpContext context)
    {
        if (!_map.IsEmpty)
        {
            var prefix = _map.PrefixForHost(context.Request.Host.Host);
            if (prefix is not null)
            {
                var path = context.Request.Path.Value ?? "/";
                if (!StartsWithSegment(path, prefix))
                    context.Request.Path = prefix + path;
            }
        }
        return _next(context);
    }

    private static bool StartsWithSegment(string path, string prefix)
    {
        if (!path.StartsWith(prefix, StringComparison.Ordinal)) return false;
        return path.Length == prefix.Length || path[prefix.Length] == '/';
    }
}
