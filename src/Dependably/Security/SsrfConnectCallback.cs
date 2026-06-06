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

    /// <param name="isBlocked">
    /// Per-IP block predicate — <see cref="SsrfGuard.IsBlockedIp"/> in production. Injected so
    /// tests can supply a permissive predicate that allows loopback (WireMock upstreams).
    /// </param>
    public SsrfConnectCallback(Func<IPAddress, bool> isBlocked) => _isBlocked = isBlocked;

    public ValueTask<Stream> ConnectAsync(
        System.Net.Http.SocketsHttpConnectionContext context,
        CancellationToken ct)
        => ConnectAsync(context.DnsEndPoint.Host, context.DnsEndPoint.Port, ct);

    // Core logic, separated from the un-constructable SocketsHttpConnectionContext so it can
    // be unit-tested directly.
    internal async ValueTask<Stream> ConnectAsync(string host, int port, CancellationToken ct)
    {
        // IP literals need no DNS lookup; hostnames are resolved once and dialed from the
        // same result set, leaving no second resolution for a rebinding attacker to flip.
        IPAddress[] candidates = IPAddress.TryParse(host, out var literal)
            ? [literal]
            : await Dns.GetHostAddressesAsync(host, ct).ConfigureAwait(false);

        if (candidates.Length == 0)
            throw new SsrfBlockedException(host);

        // Validate EVERY candidate: a split-horizon / rebinding resolver returning one public
        // and one internal address must not be able to have the internal one dialed.
        var blocked = candidates.FirstOrDefault(_isBlocked);
        if (blocked is not null)
            throw new SsrfBlockedException($"{host} -> {blocked}");

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
