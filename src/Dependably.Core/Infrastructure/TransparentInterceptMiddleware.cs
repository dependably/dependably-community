namespace Dependably.Infrastructure;

/// <summary>
/// Path rewriter for transparent-intercept deployments. Gated on a non-empty
/// <see cref="HostEcosystemMap"/> (populated from <c>HOST_ROUTING</c>) — when the inbound
/// <c>Host</c> header matches a configured ecosystem hostname, prepends the ecosystem prefix
/// (<c>/npm</c>, <c>/nuget</c>, <c>/maven</c>, <c>/rpm</c>, <c>/v2</c>) to the request path so
/// the existing prefix-routed controllers serve the request unchanged. For every ecosystem but
/// PyPI the prefix is a fixed per-host value; for PyPI it also depends on the request path
/// (<see cref="HostEcosystemMap.PrefixForHost"/>) — <c>/simple/…</c> and <c>/packages/…</c>
/// pass through unprefixed since those routes are already unprefixed, while everything else
/// (the legacy JSON API, twine's <c>/legacy/</c> upload endpoint) gets <c>/pypi</c> prepended.
///
/// Idempotent: if the path already starts with the resolved prefix, no rewrite happens. Hosts
/// not in the map (the deployment hostname, the admin UI host) pass through.
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
            string path = context.Request.Path.Value ?? "/";
            string? prefix = _map.PrefixForHost(context.Request.Host.Host, path);
            if (prefix is not null && !StartsWithSegment(path, prefix))
            {
                context.Request.Path = prefix + path;
            }
        }
        return _next(context);
    }

    private static bool StartsWithSegment(string path, string prefix)
    {
        return path.StartsWith(prefix, StringComparison.Ordinal) && (path.Length == prefix.Length || path[prefix.Length] == '/');
    }
}
