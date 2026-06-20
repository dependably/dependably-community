using System.Net;
using System.Net.Sockets;
using Dependably.Protocol;
using Dependably.Security;

namespace Dependably.Tests.Unit;

[Trait("Category", "Security")]
public class SsrfConnectCallbackTests
{
    [Fact]
    public async Task ConnectAsync_BlockedIpLiteral_ThrowsWithoutDnsOrSocket()
    {
        // 169.254.169.254 is the cloud metadata endpoint — an IP literal, so the callback
        // rejects it before any DNS lookup or socket connect.
        var cb = new SsrfConnectCallback(SsrfGuard.IsBlockedIp);

        var ex = await Assert.ThrowsAsync<SsrfBlockedException>(async () =>
            await cb.ConnectAsync("169.254.169.254", 80, CancellationToken.None));

        Assert.Contains("169.254.169.254", ex.Message);
    }

    [Theory]
    [InlineData("0.0.0.0")]   // "this host" — Linux routes to loopback
    [InlineData("0.0.0.1")]   // still in 0/8
    [InlineData("::")]        // IPv6 unspecified — routes to loopback on Linux
    public async Task ConnectAsync_ZeroOrUnspecifiedIpLiteral_Blocked(string ip)
    {
        // IP literals in the 0/8 "this host" range and the IPv6 unspecified address (::)
        // must be rejected at the connect-time gate, not merely at URL-validation time.
        var cb = new SsrfConnectCallback(SsrfGuard.IsBlockedIp);

        var ex = await Assert.ThrowsAsync<SsrfBlockedException>(async () =>
            await cb.ConnectAsync(ip, 80, CancellationToken.None));

        Assert.Contains(ip, ex.Message);
    }

    [Fact]
    public async Task ConnectAsync_PredicateBlocksEverything_ThrowsForPublicIp()
    {
        // Even a public literal is refused when the injected predicate blocks it — proving the
        // callback gates on the predicate, not a hardcoded list.
        var cb = new SsrfConnectCallback(_ => true);

        await Assert.ThrowsAsync<SsrfBlockedException>(async () =>
            await cb.ConnectAsync("8.8.8.8", 443, CancellationToken.None));
    }

    [Fact]
    public async Task ConnectAsync_PermissivePredicate_DialsLoopback()
    {
        // The permissive seam (used by integration tests for WireMock) must connect to
        // loopback even though SsrfGuard would block 127.0.0.0/8.
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var acceptTask = listener.AcceptTcpClientAsync();

        try
        {
            var cb = new SsrfConnectCallback(_ => false);

            await using var stream = await cb.ConnectAsync("127.0.0.1", port, CancellationToken.None);

            Assert.NotNull(stream);
            using var accepted = await acceptTask;   // the dial actually reached the listener
            Assert.True(accepted.Connected);
        }
        finally
        {
            listener.Stop();
        }
    }
}
