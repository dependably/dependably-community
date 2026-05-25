using System.Net;
using System.Net.Sockets;
using System.Text;
using Dependably.Infrastructure.Siem;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace Dependably.Tests.Unit;

/// <summary>
/// Extends the existing forwarder tests to cover the CefFriendlyName + CefSeverity branches
/// not exercised today and the RFC 5424 null-field paths.
/// </summary>
[Trait("Category", "Unit")]
public sealed class SyslogSiemForwarderExtendedTests
{
    private static SiemEvent Sample(
        string action = "login.success",
        string? orgId = "org-acme",
        string? actorId = "u-1",
        string? ecosystem = "npm",
        string? purl = "pkg:npm/lodash@1.0.0",
        string? detail = null) => new(
            Id: "e1", Action: action, Scope: "tenant",
            OrgId: orgId, ActorId: actorId, Ecosystem: ecosystem, Purl: purl,
            Detail: detail,
            CreatedAt: new DateTimeOffset(2026, 5, 9, 12, 30, 45, 123, TimeSpan.Zero));

    private static IConfiguration Cfg(IDictionary<string, string?> overrides) =>
        new ConfigurationBuilder().AddInMemoryCollection(overrides).Build();

    // ── Constructor: transport + format defaults ─────────────────────────────

    [Theory]
    [InlineData("udp", "syslog/udp")]
    [InlineData("UDP", "syslog/udp")]
    [InlineData("tcp", "syslog/tcp")]
    [InlineData("tls", "syslog/tls")]
    public void Name_ReflectsConfiguredTransport(string proto, string expectedName)
    {
        var sut = new SyslogSiemForwarder(Cfg(new Dictionary<string, string?>
        {
            ["SIEM_SYSLOG_HOST"] = "siem.example.com",
            ["SIEM_SYSLOG_PROTO"] = proto,
        }));
        Assert.Equal(expectedName, sut.Name);
    }

    [Fact]
    public void Constructor_PortDefaultsTo514_WhenAbsent()
    {
        // No SIEM_SYSLOG_PORT — must construct successfully with the syslog default port.
        var sut = new SyslogSiemForwarder(Cfg(new Dictionary<string, string?>
        {
            ["SIEM_SYSLOG_HOST"] = "siem.example.com"
        }));
        Assert.Equal("syslog/udp", sut.Name);
    }

    [Fact]
    public void Constructor_PortNonNumeric_FallsBackToDefault()
    {
        // Bad port string is silently ignored — the forwarder still constructs.
        var sut = new SyslogSiemForwarder(Cfg(new Dictionary<string, string?>
        {
            ["SIEM_SYSLOG_HOST"] = "siem.example.com",
            ["SIEM_SYSLOG_PORT"] = "garbage"
        }));
        Assert.Equal("syslog/udp", sut.Name);
    }

    // ── FormatCef: friendly-name + severity branch coverage ──────────────────

    [Theory]
    [InlineData("login.failure",       "Login Failure",   5)]
    [InlineData("token.created",       "Token Created",   3)]  // unknown sev defaults to 3
    [InlineData("token.revoked",       "Token Revoked",   4)]
    [InlineData("rbac.role_changed",   "Role Changed",    6)]
    [InlineData("rbac.member_added",   "Member Added",    3)]  // unknown sev defaults to 3
    [InlineData("rbac.member_removed", "Member Removed",  3)]
    [InlineData("unmapped.event",      "unmapped.event",  3)]  // fallback uses action verbatim
    public void FormatCef_FriendlyNameAndSeverity_FollowMap(string action, string friendly, int sev)
    {
        var line = SyslogSiemForwarder.FormatCef(Sample(action: action));
        Assert.Contains($"|{action}|{friendly}|{sev}|", line);
    }

    [Fact]
    public void FormatCef_OmitsOptionalFields_WhenNull()
    {
        var line = SyslogSiemForwarder.FormatCef(Sample(
            actorId: null, ecosystem: null, purl: null, orgId: null));
        Assert.DoesNotContain(" suid=", line);
        Assert.DoesNotContain(" cs1=", line);
        Assert.DoesNotContain(" cs2=", line);
        Assert.DoesNotContain(" cs3=", line);
    }

    [Fact]
    public void FormatCef_IncludesDetail_WhenPresent()
    {
        var line = SyslogSiemForwarder.FormatCef(Sample(detail: "extra context"));
        Assert.Contains("msg=extra context", line);
    }

    // ── FormatRfc5424: null-field paths ──────────────────────────────────────

    [Fact]
    public void FormatRfc5424_OmitsSdFields_WhenNull()
    {
        var line = SyslogSiemForwarder.FormatRfc5424(Sample(
            orgId: null, actorId: null, ecosystem: null, purl: null));
        // Only the SDID stays; no org=/actor=/etc.
        Assert.Contains("[dependably@0]", line);
        Assert.DoesNotContain("org=", line);
        Assert.DoesNotContain("actor=", line);
    }

    [Fact]
    public void FormatRfc5424_EmptyDetail_DoesNotBreakStructure()
    {
        var line = SyslogSiemForwarder.FormatRfc5424(Sample(detail: null));
        // Trailing message segment is empty but the structured-data + space prefix remain.
        Assert.Contains("] ", line);
    }

    // ── SendAsync transport branches — loopback listeners, no live infra ─────

    [Fact]
    public async Task SendAsync_Udp_WritesDatagramToLoopbackListener()
    {
        // Bind the receiver first so the datagram has somewhere to land.
        using var receiver = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var port = ((IPEndPoint)receiver.Client.LocalEndPoint!).Port;

        var sut = new SyslogSiemForwarder(Cfg(new Dictionary<string, string?>
        {
            ["SIEM_SYSLOG_HOST"] = "127.0.0.1",
            ["SIEM_SYSLOG_PORT"] = port.ToString(),
            ["SIEM_SYSLOG_PROTO"] = "udp",
            ["SIEM_SYSLOG_FORMAT"] = "rfc5424",
        }));

        await sut.SendAsync(Sample(action: "login.success"));

        // Receive within a generous timeout — loopback should be effectively instant.
        var recvTask = receiver.ReceiveAsync();
        var done = await Task.WhenAny(recvTask, Task.Delay(TimeSpan.FromSeconds(5)));
        Assert.Same(recvTask, done);
        var result = await recvTask;
        var payload = Encoding.UTF8.GetString(result.Buffer);
        Assert.Contains("login.success", payload);
        Assert.EndsWith("\n", payload);
    }

    [Fact]
    public async Task SendAsync_Tcp_WritesFramedLineToLoopbackListener()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            var acceptTask = listener.AcceptTcpClientAsync();

            var sut = new SyslogSiemForwarder(Cfg(new Dictionary<string, string?>
            {
                ["SIEM_SYSLOG_HOST"] = "127.0.0.1",
                ["SIEM_SYSLOG_PORT"] = port.ToString(),
                ["SIEM_SYSLOG_PROTO"] = "tcp",
                ["SIEM_SYSLOG_FORMAT"] = "cef",
            }));

            await sut.SendAsync(Sample(action: "lockout.triggered"));

            using var server = await acceptTask.WaitAsync(TimeSpan.FromSeconds(5));
            using var ns = server.GetStream();
            var buf = new byte[1024];
            // Read until the writer side has closed (forwarder disposes its TcpClient).
            using var ms = new MemoryStream();
            int read;
            while ((read = await ns.ReadAsync(buf).AsTask().WaitAsync(TimeSpan.FromSeconds(5))) > 0)
                ms.Write(buf, 0, read);

            var line = Encoding.UTF8.GetString(ms.ToArray());
            Assert.StartsWith("CEF:0|Dependably|dependably|1.0|", line);
            Assert.Contains("|lockout.triggered|Account Lockout|7|", line);
            Assert.EndsWith("\n", line);
        }
        finally
        {
            listener.Stop();
        }
    }

    [Fact]
    public async Task SendAsync_Tls_AgainstNonTlsListener_ThrowsDuringHandshake()
    {
        // Exercises the useTls branch of SendTcpAsync. A plain TCP listener will not
        // complete the TLS handshake, so we expect AuthenticateAsClientAsync to throw.
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;

            // Accept and immediately close to terminate the handshake quickly.
            _ = Task.Run(async () =>
            {
                try
                {
                    using var s = await listener.AcceptTcpClientAsync();
                    s.Close();
                }
                catch { /* listener stopped */ }
            });

            var sut = new SyslogSiemForwarder(Cfg(new Dictionary<string, string?>
            {
                ["SIEM_SYSLOG_HOST"] = "127.0.0.1",
                ["SIEM_SYSLOG_PORT"] = port.ToString(),
                ["SIEM_SYSLOG_PROTO"] = "tls",
                ["SIEM_SYSLOG_FORMAT"] = "cef",
            }));

            await Assert.ThrowsAnyAsync<Exception>(async () =>
                await sut.SendAsync(Sample()).WaitAsync(TimeSpan.FromSeconds(10)));
        }
        finally
        {
            listener.Stop();
        }
    }
}
