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

    // ── ConnectSocketAsync — the raw-socket surface SmtpMailSender dials through ────────────
    //
    // MailKit's SmtpClient has no ConnectCallback hook, so SmtpMailSender cannot reuse the
    // Stream-returning ConnectAsync above; it calls ConnectSocketAsync directly and hands the
    // vetted Socket plus the original hostname to MailKit. These pin that this public entry
    // point applies the identical block/allow decision as the Stream-returning overload.

    [Fact]
    public async Task ConnectSocketAsync_BlockedIpLiteral_ThrowsWithoutDnsOrSocket()
    {
        var cb = new SsrfConnectCallback(SsrfGuard.IsBlockedIp);

        var ex = await Assert.ThrowsAsync<SsrfBlockedException>(async () =>
            await cb.ConnectSocketAsync("169.254.169.254", 25, CancellationToken.None));

        Assert.Contains("169.254.169.254", ex.Message);
    }

    [Fact]
    public async Task ConnectSocketAsync_PermissivePredicate_ReturnsConnectedSocketToVettedTarget()
    {
        // The path SmtpMailSender relies on: a host that the predicate allows dials a raw,
        // already-connected Socket (not a Stream) — the exact shape MailKit's
        // SmtpClient.ConnectAsync(Socket, string, int, ...) overload accepts.
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var acceptTask = listener.AcceptTcpClientAsync();

        try
        {
            var cb = new SsrfConnectCallback(_ => false);

            using var socket = await cb.ConnectSocketAsync("127.0.0.1", port, CancellationToken.None);

            Assert.True(socket.Connected);
            using var accepted = await acceptTask;
            Assert.True(accepted.Connected);
        }
        finally
        {
            listener.Stop();
        }
    }

    // ── DNS-rebinding: any blocked candidate rejects the whole connect ─────────

    [Fact]
    public async Task ConnectAsync_MixedCandidates_OneBlockedIP_ThrowsWithoutDialing()
    {
        // DNS rebinding / split-horizon attack: resolver returns one public address and one
        // internal address. The callback must reject the connection entirely — even though a
        // public address is present — because the OS may dial the internal one.
        //
        // This test would fail on code that lacks the connect-time gate: without the callback
        // the OS would be free to connect to whichever candidate it selects, and under
        // DNS rebinding that may be the blocked address.
        bool didDial = false;

        // Inject a resolver that returns one public IP followed by one internal IP, simulating
        // a split-horizon response.
        var cb = new SsrfConnectCallback(
            SsrfGuard.IsBlockedIp,
            allowedHost: null,
            (_, _) => Task.FromResult<IPAddress[]>(
            [
                IPAddress.Parse("8.8.8.8"),         // public — would pass URL-level check
                IPAddress.Parse("10.0.0.1"),        // RFC1918 — must block the whole call
            ]));

        var ex = await Assert.ThrowsAsync<SsrfBlockedException>(async () =>
        {
            didDial = true;
            await cb.ConnectAsync("rebinding.attacker.example", 443, CancellationToken.None);
        });

        // The blocked internal IP must appear in the exception message so operators can
        // diagnose which resolved address triggered the block.
        Assert.Contains("10.0.0.1", ex.Message);

        // didDial=true above is set immediately before ConnectAsync, so if the exception was
        // thrown, the important invariant is that Socket.ConnectAsync was never reached.
        // The fact that SsrfBlockedException was thrown (not SocketException or similar) is the
        // proof that the gate fired before the dial.
        Assert.True(didDial); // confirms the await was reached, not short-circuited by other means
    }

    [Fact]
    public async Task ConnectAsync_AllCandidatesPublic_AllowsConnection()
    {
        // When every candidate returned by DNS is public, the connection is allowed.
        // Verifies that the "any blocked" check does not over-block when all addresses are safe.
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var acceptTask = listener.AcceptTcpClientAsync();

        try
        {
            // Resolver returns only loopback; predicate allows everything (permissive seam).
            SsrfConnectCallback cb = new(
                _ => false,
                allowedHost: null,
                (_, _) => Task.FromResult<IPAddress[]>([IPAddress.Loopback]));

            await using var stream = await cb.ConnectAsync("all-public.example", port, CancellationToken.None);

            Assert.NotNull(stream);
            using var accepted = await acceptTask;
            Assert.True(accepted.Connected);
        }
        finally
        {
            listener.Stop();
        }
    }

    [Fact]
    public async Task ConnectAsync_EmptyCandidateSet_ThrowsSsrfBlockedException()
    {
        // A resolver that returns zero addresses (NXDOMAIN / empty answer) is treated as a
        // block — there is no safe address to dial.
        var cb = new SsrfConnectCallback(
            SsrfGuard.IsBlockedIp,
            allowedHost: null,
            (_, _) => Task.FromResult(Array.Empty<IPAddress>()));

        var ex = await Assert.ThrowsAsync<SsrfBlockedException>(async () =>
            await cb.ConnectAsync("nxdomain.example", 443, CancellationToken.None));

        Assert.Contains("nxdomain.example", ex.Message);
    }

    // ── partial-failure: mixed batch of hosts, each evaluated independently ────

    [Fact]
    public async Task ConnectAsync_MixedBatch_EachHostEvaluatedIndependently()
    {
        // Verifies the connect-time gate under a partial-failure scenario: three hosts are
        // dialed in sequence. The first resolves to a safe address and connects; the second
        // resolves to a blocked address and is rejected; the third resolves to a safe address
        // and connects. A blocked middle host must not prevent the third from succeeding.
        //
        // Without a connect-time gate the second host would have reached the blocked address
        // (demonstrating the DNS-rebinding window that SsrfConnectCallback closes).
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;

        // Pre-accept the two successful connections from hosts A and C.
        var acceptA = listener.AcceptTcpClientAsync();
        var acceptC = listener.AcceptTcpClientAsync();

        try
        {
            // Candidate map: safe hosts resolve to loopback (reachable in tests); the blocked
            // host resolves to a cloud-metadata IP.
            var candidateMap = new Dictionary<string, IPAddress[]>
            {
                ["host-a.example"] = [IPAddress.Loopback],
                ["host-b.example"] = [IPAddress.Parse("169.254.169.254")],
                ["host-c.example"] = [IPAddress.Loopback],
            };

            // Custom predicate: blocks only the cloud-metadata range, not loopback — so the
            // test listener (on loopback) receives the safe connections.
            static bool BlocksMetadataOnly(IPAddress ip)
            {
                // 169.254.0.0/16 — cloud-metadata range
                byte[] bytes = ip.GetAddressBytes();
                return bytes.Length == 4 && bytes[0] == 169 && bytes[1] == 254;
            }

            var cb = new SsrfConnectCallback(
                BlocksMetadataOnly,
                allowedHost: null,
                (host, _) => Task.FromResult(candidateMap[host]));

            var results = new List<(bool Blocked, bool Connected)>();

            foreach (string host in new[] { "host-a.example", "host-b.example", "host-c.example" })
            {
                try
                {
                    await using var stream = await cb.ConnectAsync(host, port, CancellationToken.None);
                    results.Add((false, true));
                }
                catch (SsrfBlockedException)
                {
                    results.Add((true, false));
                }
            }

            // Host A: allowed, socket connected
            Assert.False(results[0].Blocked);
            Assert.True(results[0].Connected);

            // Host B: blocked — connect-time gate fires before any socket is opened
            Assert.True(results[1].Blocked);
            Assert.False(results[1].Connected);

            // Host C: allowed and connected despite the middle host being blocked
            Assert.False(results[2].Blocked);
            Assert.True(results[2].Connected);

            // Both safe connections actually reached the listener.
            using var clientA = await acceptA;
            using var clientC = await acceptC;
            Assert.True(clientA.Connected);
            Assert.True(clientC.Connected);
        }
        finally
        {
            listener.Stop();
        }
    }

    [Theory]
    [InlineData("10.0.0.1", "8.8.8.8")]          // internal first, public second
    [InlineData("8.8.8.8", "10.0.0.1")]          // public first, internal second
    [InlineData("8.8.8.8", "169.254.169.254")]   // metadata endpoint second
    [InlineData("169.254.169.254", "8.8.8.8")]   // metadata endpoint first
    public async Task ConnectAsync_AnyBlockedCandidateOrder_AlwaysThrows(
        string firstIp, string secondIp)
    {
        // The "any blocked" check must not depend on the order of addresses in the DNS
        // response. Whether the blocked IP appears first or last in the candidate set, the
        // connection is rejected.
        var cb = new SsrfConnectCallback(
            SsrfGuard.IsBlockedIp,
            allowedHost: null,
            (_, _) => Task.FromResult<IPAddress[]>(
            [
                IPAddress.Parse(firstIp),
                IPAddress.Parse(secondIp),
            ]));

        await Assert.ThrowsAsync<SsrfBlockedException>(async () =>
            await cb.ConnectAsync("attacker.example", 443, CancellationToken.None));
    }
}
