using System.Net;

namespace Dependably.Infrastructure;

/// <summary>
/// Records the request's raw socket peer in <c>HttpContext.Items</c> before
/// <c>ForwardedHeadersMiddleware</c> can overwrite <c>Connection.RemoteIpAddress</c> with the
/// client address carried in <c>X-Forwarded-For</c>. It must therefore be registered ahead of
/// <c>UseForwardedHeaders()</c>.
///
/// Two different questions are asked of a request's origin, and only one of them is answered by
/// <c>Connection.RemoteIpAddress</c> once forwarding is in play. "Which client is this?" is the
/// forwarded value — what the /metrics allowlist, audit <c>source_ip</c>, and rate-limit partitions
/// want. "Did this request come through the trusted edge proxy?" is the socket peer, and it is the
/// only thing that can authenticate a header the edge injects: after the rewrite, the connection
/// address is a client address the proxy chose, and <c>X-Original-For</c> is caller-controlled on
/// exactly the requests that did not go through a trusted proxy.
/// </summary>
public sealed class OriginalPeerMiddleware
{
    /// <summary>
    /// <c>HttpContext.Items</c> key holding the raw socket peer <see cref="IPAddress"/>.
    /// </summary>
    public const string HttpItemsKey = "OriginalPeerIp";

    private readonly RequestDelegate _next;

    public OriginalPeerMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var peer = context.Connection.RemoteIpAddress;
        if (peer is not null)
        {
            context.Items[HttpItemsKey] = peer;
        }

        await _next(context);
    }

    /// <summary>
    /// The socket peer recorded for this request, or null when it was never recorded — an
    /// in-memory request with no connection, or a pipeline that does not register this middleware.
    /// Callers treat null as "not the trusted proxy": the peer identity is a trust input, so an
    /// absent one denies rather than falls back to the (possibly rewritten)
    /// <c>Connection.RemoteIpAddress</c>.
    /// </summary>
    public static IPAddress? Read(HttpContext context) =>
        context.Items.TryGetValue(HttpItemsKey, out object? value) ? value as IPAddress : null;
}
