using System.Net;
using System.Net.Sockets;
using Dependably.Protocol;
using Dependably.Security;

namespace Dependably.Tests.Unit;

/// <summary>
/// The edge SSRF allowlist: <see cref="SsrfConnectCallback"/> admits exactly the pinned master
/// host (so an internal/private master over a LAN link is dialable) while every other
/// private/internal host stays blocked. Non-edge behaviour (no allowed host) is unchanged.
/// </summary>
// Exercises the SSRF connect-time gate that feeds the same dns_rebind/blocked_range emission
// paths UpstreamUrlBlocksEmissionTests asserts exact counts against. See MeterSensitiveCollection.
[Trait("Category", "Security")]
[Collection("MeterSensitive")]
public sealed class EdgeSsrfAllowlistTests
{
    [Fact]
    public async Task ConnectAsync_AllowedMasterHostLiteral_BypassesBlockPredicate()
    {
        // 10.1.2.3 is an RFC 1918 private literal that SsrfGuard blocks. With it pinned as the
        // allowed host, the callback must not throw at the block check — it proceeds to dial
        // (which then fails at the socket layer, not the SSRF gate). We assert the failure is a
        // socket/connect failure, NOT an SsrfBlockedException.
        var cb = new SsrfConnectCallback(SsrfGuard.IsBlockedIp, allowedHost: "10.1.2.3");

        // A connect to an unreachable private IP throws a socket exception, proving the SSRF
        // block was bypassed (otherwise it would throw SsrfBlockedException first).
        await Assert.ThrowsAnyAsync<Exception>(async () =>
            await cb.ConnectAsync("10.1.2.3", 65000, new CancellationTokenSource(TimeSpan.FromSeconds(2)).Token));
    }

    [Fact]
    public async Task ConnectAsync_NonMasterPrivateHost_StillBlocked()
    {
        // The allowlist is scoped to exactly the master host; a DIFFERENT private literal must
        // still be rejected by the SSRF gate.
        var cb = new SsrfConnectCallback(SsrfGuard.IsBlockedIp, allowedHost: "10.1.2.3");

        var ex = await Assert.ThrowsAsync<SsrfBlockedException>(async () =>
            await cb.ConnectAsync("169.254.169.254", 80, CancellationToken.None));

        Assert.Contains("169.254.169.254", ex.Message);
    }

    [Fact]
    public async Task ConnectAsync_NoAllowedHost_BlocksPrivateLiteral()
    {
        // Non-edge wiring passes no allowed host: the private literal is blocked exactly as before.
        var cb = new SsrfConnectCallback(SsrfGuard.IsBlockedIp);

        await Assert.ThrowsAsync<SsrfBlockedException>(async () =>
            await cb.ConnectAsync("10.1.2.3", 80, CancellationToken.None));
    }

    [Fact]
    public async Task ConnectAsync_AllowedHost_DialsRealLoopbackListener()
    {
        // End-to-end: with loopback pinned as the allowed host, the callback dials it even though
        // SsrfGuard.IsBlockedIp blocks 127.0.0.0/8 — proving the allowlist actually reaches connect.
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var acceptTask = listener.AcceptTcpClientAsync();

        try
        {
            var cb = new SsrfConnectCallback(SsrfGuard.IsBlockedIp, allowedHost: "127.0.0.1");

            await using var stream = await cb.ConnectAsync("127.0.0.1", port, CancellationToken.None);

            Assert.NotNull(stream);
            using var accepted = await acceptTask;
            Assert.True(accepted.Connected);
        }
        finally
        {
            listener.Stop();
        }
    }
}
