using System.Net;
using System.Net.Mail;

namespace Dependably.Infrastructure.Mail;

/// <summary>
/// Delivers invite emails via SMTP using <see cref="SmtpClient"/>.
/// Configuration is read from the following keys (env-var form shown):
/// <list type="bullet">
///   <item><c>SMTP_HOST</c> — relay hostname (required; absence disables email delivery)</item>
///   <item><c>SMTP_PORT</c> — relay port, default 587</item>
///   <item><c>SMTP_USERNAME</c> — relay auth username (optional)</item>
///   <item><c>SMTP_PASSWORD</c> — relay auth password (optional, never logged)</item>
///   <item><c>SMTP_FROM</c> — envelope From address (required when SMTP_HOST is set)</item>
///   <item><c>SMTP_STARTTLS</c> — enable STARTTLS, default true</item>
/// </list>
/// </summary>
public sealed class SmtpInviteMailer : IInviteMailer
{
    private readonly string _host;
    private readonly int _port;
    private readonly string? _username;
    private readonly string? _password;
    private readonly string _from;
    private readonly bool _enableSsl;
    private readonly ILogger<SmtpInviteMailer> _logger;

    // SmtpClient.SendMailAsync honours the client-level Timeout only for synchronous
    // operations; the async path uses the cancellation token passed to SendMailAsync.
    // We add a short timeout anyway as defence-in-depth for environments that disable
    // async cancel propagation.
    private const int SmtpTimeoutMs = 15_000;

    public SmtpInviteMailer(IConfiguration config, ILogger<SmtpInviteMailer> logger)
    {
        _logger = logger;

        _host = config["SMTP_HOST"]
            ?? throw new InvalidOperationException("SMTP_HOST is required for SmtpInviteMailer.");

        _port = int.TryParse(config["SMTP_PORT"], out int p) ? p : 587;

        _username = config["SMTP_USERNAME"];
        _password = config["SMTP_PASSWORD"];

        _from = config["SMTP_FROM"]
            ?? throw new InvalidOperationException(
                "SMTP_FROM is required when SMTP_HOST is set — set it to the envelope From address (e.g. invites@example.com).");

        // SMTP_STARTTLS defaults true; explicit "false" or "0" disables.
        string? startTls = config["SMTP_STARTTLS"];
        _enableSsl = string.IsNullOrWhiteSpace(startTls)
            || !(string.Equals(startTls, "false", StringComparison.OrdinalIgnoreCase)
                 || string.Equals(startTls, "0", StringComparison.OrdinalIgnoreCase));
    }

    public async Task SendInviteAsync(string toAddress, string orgName, string inviteLink, DateTimeOffset expiresAt, CancellationToken ct = default)
    {
        string body =
            $"You have been invited to join {orgName} on Dependably.\n\n" +
            $"Accept your invitation using the link below. " +
            $"The link expires at {expiresAt:yyyy-MM-dd HH:mm} UTC.\n\n" +
            $"{inviteLink}\n\n" +
            "If you were not expecting this invitation, you can ignore this email.\n";

        using var client = BuildClient();
        using var message = new MailMessage(_from, toAddress)
        {
            Subject = $"You've been invited to {orgName} on Dependably",
            Body = body,
            IsBodyHtml = false,
        };

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(SmtpTimeoutMs);

        await client.SendMailAsync(message, cts.Token);

        _logger.LogInformation(
            "Invite email delivered via SMTP to {RecipientDomain} for org {OrgName}.",
            ExtractDomain(toAddress),
            orgName);
    }

    private SmtpClient BuildClient()
    {
        // TLS is on by default; SMTP_STARTTLS=false is an explicit operator opt-out for loopback/internal relays.
#pragma warning disable S5332
        var client = new SmtpClient(_host, _port)
        {
            EnableSsl = _enableSsl,
            Timeout = SmtpTimeoutMs,
        };
#pragma warning restore S5332

        if (!string.IsNullOrWhiteSpace(_username))
        {
            client.Credentials = new NetworkCredential(_username, _password);
        }

        return client;
    }

    // Log only the domain portion of the recipient address so PII (the local-part) never
    // appears in structured logs. The invite audit_log entry (see OrgInvitesController)
    // is the sanctioned record of the recipient email.
    private static string ExtractDomain(string address)
    {
        int at = address.IndexOf('@', StringComparison.Ordinal);
        return at >= 0 ? address[(at + 1)..] : "[unknown]";
    }
}
