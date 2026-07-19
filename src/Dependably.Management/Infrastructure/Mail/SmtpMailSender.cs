using System.Net.Sockets;
using Dependably.Security;
using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;

namespace Dependably.Infrastructure.Mail;

/// <summary>
/// The single choke point for every outbound email Dependably sends — invites, per-org alert
/// delivery, and the instance/org email-config test-send endpoints all funnel through this
/// class. MailKit (rather than <see cref="System.Net.Mail.SmtpClient"/>) is required because the
/// <c>starttls|ssl|none</c> security vocabulary needs implicit TLS on connect (port 465), which
/// <c>SmtpClient</c> cannot do. Not sealed and <see cref="SendAsync"/> is virtual solely so the
/// alert email delivery queue's unit tests can substitute a recording fake for the live MailKit
/// send — every production caller still resolves the concrete class from DI.
///
/// MailKit's <see cref="SmtpClient"/> has no <c>ConnectCallback</c> hook the way
/// <see cref="System.Net.Http.SocketsHttpHandler"/> does for every other outbound transport in
/// this codebase (upstream registries, webhooks, Slack, OSV, threat feeds), so it cannot reuse
/// that machinery directly. Instead, <see cref="SendAsync"/> resolves and vets the host itself
/// via <see cref="SsrfConnectCallback.ConnectSocketAsync"/> — the same resolve-once/dial-what-was-
/// checked guarantee — and hands MailKit the already-connected, already-vetted
/// <see cref="Socket"/> plus the original hostname (used only for TLS SNI/certificate-name
/// validation), so no second, unvetted DNS lookup happens inside the client.
/// </summary>
public class SmtpMailSender
{
    // SmtpClient.ConnectAsync/SendAsync honour the CancellationToken directly, but a short
    // client-side timeout is defence-in-depth against a relay that accepts the TCP connection
    // and then never responds.
    private const int SmtpTimeoutMs = 15_000;

    private readonly SsrfConnectCallback _connectGuard;

    public SmtpMailSender(SsrfConnectCallback connectGuard)
    {
        _connectGuard = connectGuard;
    }

    public virtual async Task SendAsync(
        SmtpTransportSettings transport,
        IReadOnlyList<string> to,
        string subject,
        string body,
        CancellationToken ct = default)
    {
        var message = BuildValidatedMessage(transport, to, subject, body);
        await SendMessageAsync(transport, message, ct).ConfigureAwait(false);
    }

    // Validates the request and builds the MIME message. Synchronous and I/O-free, so a malformed
    // request (missing recipient, host, or from-address) fails before any socket connect attempt.
    private static MimeMessage BuildValidatedMessage(
        SmtpTransportSettings transport, IReadOnlyList<string> to, string subject, string body)
    {
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentNullException.ThrowIfNull(to);
        if (to.Count == 0)
        {
            throw new ArgumentException("At least one recipient is required.", nameof(to));
        }

        if (string.IsNullOrWhiteSpace(transport.Host) || string.IsNullOrWhiteSpace(transport.FromAddress))
        {
            throw new InvalidOperationException("SmtpTransportSettings.Host and FromAddress are required to send.");
        }

        var message = new MimeMessage();
        message.From.Add(MailboxAddress.Parse(transport.FromAddress));
        foreach (string recipient in to)
        {
            message.To.Add(MailboxAddress.Parse(recipient));
        }

        // CR/LF-stripped: a subject sourced from user-controlled data (org name, etc.) must never
        // be able to inject additional headers into the raw SMTP DATA stream.
        message.Subject = subject.Replace("\r", "").Replace("\n", "");
        message.Body = new TextPart("plain") { Text = body };

        return message;
    }

    // Connects through the SSRF-vetted socket, authenticates if configured, and sends the
    // already-built message.
    private async Task SendMessageAsync(SmtpTransportSettings transport, MimeMessage message, CancellationToken ct)
    {
        // Non-null: BuildValidatedMessage already rejected a blank Host before this method is reached.
        string host = transport.Host!;

        using var client = new SmtpClient();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(SmtpTimeoutMs);

        // Resolve + vet the host and dial it ourselves — the authoritative SSRF gate for this
        // transport (see class remarks). Throws SsrfBlockedException for a blocked/unresolvable
        // host, which propagates to the caller's generic send-failure handling like any other
        // connect error.
        var socket = await _connectGuard.ConnectSocketAsync(host, transport.Port, cts.Token)
            .ConfigureAwait(false);
        try
        {
            await client.ConnectAsync(socket, host, transport.Port, ToSecureSocketOptions(transport.Security), cts.Token)
                .ConfigureAwait(false);
        }
        catch
        {
            socket.Dispose();
            throw;
        }

        if (!string.IsNullOrWhiteSpace(transport.Username) && !string.IsNullOrWhiteSpace(transport.Password))
        {
            await client.AuthenticateAsync(transport.Username, transport.Password, cts.Token).ConfigureAwait(false);
        }

        await client.SendAsync(message, cts.Token).ConfigureAwait(false);
        await client.DisconnectAsync(true, cts.Token).ConfigureAwait(false);
    }

    /// <summary>Maps the <c>starttls|ssl|none</c> vocabulary onto MailKit's connection modes.</summary>
    internal static SecureSocketOptions ToSecureSocketOptions(string security) => security?.ToLowerInvariant() switch
    {
        "ssl" => SecureSocketOptions.SslOnConnect,
        "none" => SecureSocketOptions.None,
        _ => SecureSocketOptions.StartTls,
    };
}
