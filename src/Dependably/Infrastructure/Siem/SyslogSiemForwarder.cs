using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;

namespace Dependably.Infrastructure.Siem;

/// <summary>
/// Sends each event as one syslog message over UDP, TCP, or TLS. Format selectable
/// via <c>SIEM_SYSLOG_FORMAT</c>: <c>cef</c> (default; matches the CEF formatter used by
/// <c>SiemController</c>'s pull endpoint) or <c>rfc5424</c>. The CEF body uses the same
/// escape rules as the controller so collectors that already parse Dependably's pull-API
/// output ingest the push stream identically.
///
/// Connections are short-lived: each <see cref="SendAsync"/> opens, writes, and closes.
/// That's slower than a long-lived connection but simpler and safer in the face of partial
/// failures — the <see cref="SiemForwarderQueue"/> handles retry. For high-volume sites,
/// upgrading to a connection pool is a follow-up.
/// </summary>
public sealed class SyslogSiemForwarder : ISiemForwarder
{
    private readonly string _host;
    private readonly int _port;
    private readonly Transport _transport;
    private readonly Format _format;

    public SyslogSiemForwarder(IConfiguration config)
    {
        _host = config["SIEM_SYSLOG_HOST"]
            ?? throw new InvalidOperationException("SIEM_SYSLOG_HOST is required for SyslogSiemForwarder.");
        _port = int.TryParse(config["SIEM_SYSLOG_PORT"], out int p) && p > 0 ? p : 514;
        _transport = (config["SIEM_SYSLOG_PROTO"] ?? "udp").Trim().ToLowerInvariant() switch
        {
            "udp" => Transport.Udp,
            "tcp" => Transport.Tcp,
            "tls" => Transport.Tls,
            var other => throw new InvalidOperationException(
                $"SIEM_SYSLOG_PROTO must be udp, tcp, or tls; got '{other}'.")
        };
        _format = (config["SIEM_SYSLOG_FORMAT"] ?? "cef").Trim().ToLowerInvariant() switch
        {
            "cef" => Format.Cef,
            "rfc5424" => Format.Rfc5424,
            var other => throw new InvalidOperationException(
                $"SIEM_SYSLOG_FORMAT must be cef or rfc5424; got '{other}'.")
        };
    }

    public string Name => $"syslog/{_transport.ToString().ToLowerInvariant()}";

    public async Task SendAsync(SiemEvent ev, CancellationToken ct = default)
    {
        string line = _format == Format.Cef ? FormatCef(ev) : FormatRfc5424(ev);
        byte[] bytes = Encoding.UTF8.GetBytes(line + "\n");

        switch (_transport)
        {
            case Transport.Udp:
                await SendUdpAsync(bytes, ct);
                break;
            case Transport.Tcp:
                await SendTcpAsync(bytes, useTls: false, ct);
                break;
            case Transport.Tls:
                await SendTcpAsync(bytes, useTls: true, ct);
                break;
        }
    }

    private async Task SendUdpAsync(byte[] bytes, CancellationToken ct)
    {
        using var udp = new UdpClient();
        await udp.SendAsync(bytes, _host, _port, ct);
    }

    private async Task SendTcpAsync(byte[] bytes, bool useTls, CancellationToken ct)
    {
        using var tcp = new TcpClient();
        await tcp.ConnectAsync(_host, _port, ct);
        Stream stream = tcp.GetStream();
        if (useTls)
        {
            var ssl = new SslStream(stream, leaveInnerStreamOpen: false);
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = _host,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13
            }, ct);
            stream = ssl;
        }
        await stream.WriteAsync(bytes, ct);
        await stream.FlushAsync(ct);
        if (stream is SslStream tlsStream)
        {
            await tlsStream.DisposeAsync();
        }
    }

    /// <summary>
    /// CEF body. Mirrors <c>SiemController.CefResult</c> — same field mapping and same escape rules.
    /// Both formatters should converge into a shared helper in a follow-up; for now they are
    /// kept as parallel small implementations to avoid churn in the controller.
    /// </summary>
    internal static string FormatCef(SiemEvent ev)
    {
        string sig = CefEscape(ev.Action);
        string name = CefFriendlyName(ev.Action);
        int sev = CefSeverity(ev.Action);
        var ext = new StringBuilder();
        ext.Append($"rt={ev.CreatedAt:yyyyMMddHHmmss.fffZ}");
        if (ev.ActorId is not null)
        {
            ext.Append($" suid={CefEscape(ev.ActorId)}");
        }

        if (ev.OrgId is not null)
        {
            ext.Append($" cs1={CefEscape(ev.OrgId)} cs1Label=OrgId");
        }

        if (ev.Ecosystem is not null)
        {
            ext.Append($" cs2={CefEscape(ev.Ecosystem)} cs2Label=Ecosystem");
        }

        if (ev.Purl is not null)
        {
            ext.Append($" cs3={CefEscape(ev.Purl)} cs3Label=Purl");
        }

        if (ev.Detail is not null)
        {
            ext.Append($" msg={CefEscape(ev.Detail)}");
        }

        return $"CEF:0|Dependably|dependably|1.0|{sig}|{name}|{sev}|{ext}";
    }

    /// <summary>
    /// RFC 5424 syslog line. Facility/severity hard-coded to local0/info; structured-data
    /// uses the SDID <c>dependably@0</c> for our fields. Hostname falls back to "dependably"
    /// when <see cref="Dns.GetHostName"/> isn't available on the deployment.
    /// </summary>
    internal static string FormatRfc5424(SiemEvent ev)
    {
        const int prival = 16 * 8 + 6;  // local0.info
        string ts = ev.CreatedAt.ToString("yyyy-MM-ddTHH:mm:ss.fffzzz");
        string hostname;
        try { hostname = Dns.GetHostName() ?? "dependably"; }
        catch { hostname = "dependably"; }

        var sd = new StringBuilder("[dependably@0");
        if (ev.OrgId is not null)
        {
            sd.Append($" org=\"{Rfc5424Escape(ev.OrgId)}\"");
        }

        if (ev.ActorId is not null)
        {
            sd.Append($" actor=\"{Rfc5424Escape(ev.ActorId)}\"");
        }

        if (ev.Ecosystem is not null)
        {
            sd.Append($" ecosystem=\"{Rfc5424Escape(ev.Ecosystem)}\"");
        }

        if (ev.Purl is not null)
        {
            sd.Append($" purl=\"{Rfc5424Escape(ev.Purl)}\"");
        }

        sd.Append(']');

        string msg = ev.Detail ?? "";
        return $"<{prival}>1 {ts} {hostname} dependably - {ev.Action} {sd} {msg}";
    }

    private static string CefEscape(string s) =>
        s.Replace("\\", "\\\\").Replace("|", "\\|").Replace("=", "\\=").Replace("\n", "\\n").Replace("\r", "\\r");

    private static string Rfc5424Escape(string s) =>
        s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("]", "\\]");

    private static string CefFriendlyName(string action) => action switch
    {
        "login.success" => "Login Success",
        "login.failure" => "Login Failure",
        "lockout.triggered" => "Account Lockout",
        "token.created" => "Token Created",
        "token.revoked" => "Token Revoked",
        "rbac.role_changed" => "Role Changed",
        "rbac.member_added" => "Member Added",
        "rbac.member_removed" => "Member Removed",
        _ => action,
    };

    private static int CefSeverity(string action) => action switch
    {
        "lockout.triggered" => 7,
        "login.failure" => 5,
        "login.success" => 3,
        "token.revoked" => 4,
        "rbac.role_changed" => 6,
        _ => 3,
    };

    private enum Transport { Udp, Tcp, Tls }
    private enum Format { Cef, Rfc5424 }
}
