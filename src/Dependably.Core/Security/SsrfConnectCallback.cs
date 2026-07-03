using System.Net;
using System.Net.Sockets;
using Dependably.Protocol;

namespace Dependably.Security;

/// <summary>
/// A <see cref="System.Net.Http.SocketsHttpHandler.ConnectCallback"/> that closes the
/// DNS-rebinding TOCTOU window. For every connection the handler opens it resolves the
/// target host, rejects the connection if <em>any</em> resolved address is in a blocked
/// range, and then dials one of those already-vetted addresses directly — so the IP
/// connected to is always the IP that was validated.
///
/// Because the handler invokes this callback for every new connection — the initial
/// request, each redirect hop, and on every named client it is wired onto — it is the
/// authoritative SSRF gate regardless of what the URL-level pre-check
/// (<see cref="UpstreamUrlValidator"/>) saw.
/// </summary>
public sealed class SsrfConnectCallback
{
    private readonly Func<IPAddress, bool> _isBlocked;
    private readonly string? _allowedHost;

    /// <param name="isBlocked">
    /// Per-IP block predicate — <see cref="SsrfGuard.IsBlockedIp"/> in production. Injected so
    /// tests can supply a permissive predicate that allows loopback (WireMock upstreams).
    /// </param>
    /// <param name="allowedHost">
    /// A single exact host (edge mode's <c>EDGE_MASTER_URL</c> host) that bypasses the block
    /// predicate so an internal/private master over a LAN link is reachable. Null (the default)
    /// leaves the block check fully in force — non-edge behaviour is unchanged. Only this exact
    /// host is exempted; every other private/internal host stays blocked.
    /// </param>
    public SsrfConnectCallback(Func<IPAddress, bool> isBlocked, string? allowedHost = null)
    {
        _isBlocked = isBlocked;
        _allowedHost = string.IsNullOrEmpty(allowedHost) ? null : allowedHost;
    }

    public ValueTask<Stream> ConnectAsync(
        System.Net.Http.SocketsHttpConnectionContext context,
        CancellationToken ct)
        => ConnectAsync(context.DnsEndPoint.Host, context.DnsEndPoint.Port, ct);

    // Core logic, separated from the un-constructable SocketsHttpConnectionContext so it can
    // be unit-tested directly.
    internal async ValueTask<Stream> ConnectAsync(string host, int port, CancellationToken ct)
    {
        // Edge allowlist: the exact master host bypasses the IP block predicate so an internal
        // master is dialable; all other hosts run the full block check unchanged.
        bool hostAllowed = _allowedHost is not null
            && string.Equals(host, _allowedHost, StringComparison.OrdinalIgnoreCase);

        // IP literals need no DNS lookup; hostnames are resolved once and dialed from the
        // same result set, leaving no second resolution for a rebinding attacker to flip.
        var candidates = IPAddress.TryParse(host, out var literal)
            ? [literal]
            : await Dns.GetHostAddressesAsync(host, ct).ConfigureAwait(false);

        if (candidates.Length == 0)
        {
            throw new SsrfBlockedException(host);
        }

        // Validate EVERY candidate: a split-horizon / rebinding resolver returning one public
        // and one internal address must not be able to have the internal one dialed. The edge
        // master host is the sole exemption — an operator-pinned trusted upstream.
        if (!hostAllowed)
        {
            var blocked = candidates.FirstOrDefault(_isBlocked);
            if (blocked is not null)
            {
                throw new SsrfBlockedException($"{host} -> {blocked}");
            }
        }

        var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            await socket.ConnectAsync(candidates, port, ct).ConfigureAwait(false);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }
}
